(*Initial DHCP- need to hashtables, dynamic allocation only,server IP is always this server, no renewals or rebinding cases,
no probing before reusing address,no customisation of hardware options, reading params from config file (WIP), account for clock drift*)

(*Features implemented:

* Storage as lists
* Address leasing and releasing
* Single range of addresses
* Necessary options: serverID and lease length
* Requested lease
* Decline and release
* Requested address

*)


(* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
* WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
* MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
* ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
* WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
* ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
* OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*)

open Lwt.Infix;;
open Printf;;
open OS;;

module Make (Console:V1_LWT.CONSOLE)
  (Clock:V1.CLOCK)
  (Stack:V1_LWT.STACKV4) = struct

  type reserved_address = {
    reserved_ip_address: Ipaddr.V4.t;
    xid: Cstruct.uint32;
    reservation_timestamp: float;
  }
    
  type in_use_address = { (*this is the value associated with the clientID key*)
    lease_length:int32;
    lease_timestamp:float;
    ip_address: Ipaddr.V4.t;
  }
    
  (*TODO: use client ID to differentiate explicit ID from hardware address, allowing different hardware types.*)  
    
  type clientID = string;; (*According to RFC 2131, this should be the client's hardware address unless an explicit identifier is provided. The RFC states that the ID must be unique
    within the subnet, but the onus is on the client to ensure this if it chooses to use an explicit identifier: the server shouldn't need to check it for uniqueness. The
    full identifier is the combination of subnet and identifier, but the subnet is implicit in this implementation*)
  
  type subnet = {
    subnet: Ipaddr.V4.t;
    netmask: Ipaddr.V4.t;
    parameters: Dhcpv4_option.t list;
    max_lease_length: int32;
    default_lease_length: int32;
    reserved_addresses:(clientID*reserved_address) list ref;
    in_use_addresses:(clientID*in_use_address) list ref;
    available_addresses: Ipaddr.V4.t list ref;
    serverIP: Ipaddr.V4.t; (*The IP address of the interface that should be used to communicate with hosts on this subnet*)
  }
    
  type t = {
    c: Console.t;
    stack: Stack.t;
    server_subnet: subnet; (*A handle on the subnet that the server lives on, convenient for allocating addresses to hosts on the same subnet as the server*)
    serverIPs: Ipaddr.V4.t list;
    subnets: subnet list;
    global_parameters:  Dhcpv4_option.t list;
  }

  cstruct dhcp {
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t chaddr[16];
    uint8_t sname[64];
    uint8_t file[128];
    uint32_t cookie
  } as big_endian
    
  cenum mode {
    BootRequest = 1;
    BootReply
  } as uint8_t
  
  exception Error of string;;
  
  (*Various helper functions*)
    
  let rec list_gen(bottom,top) = (*Generate a pool of available IP addresses*)
    let a = Ipaddr.V4.to_int32 bottom in
    let b = Ipaddr.V4.to_int32 top in
    if a>b then []
    else bottom::list_gen(Ipaddr.V4.of_int32(Int32.add a Int32.one),top);; (*TODO: this function requires an ugly conversion to int32 and back for incrementing/comparison, find more elegant solution*)
 
  let rec find_subnet ip_address subnets = (*Match an IP address to a subnet*)
    let routing_prefix netmask address=
      let open Ipaddr.V4 in
      let x = to_int32 address in
      let y = to_int32 netmask in
      of_int32(Int32.logand x y)
    in
    let compare_address_to_subnet subnet =
      let prefix = routing_prefix (subnet.netmask) in
      (prefix subnet.subnet)=(prefix ip_address)
    in
    match subnets with
    |[] -> raise (Error ("Subnet not found for subnet "^Ipaddr.V4.to_string(ip_address)))
    |h::t ->
      if (compare_address_to_subnet h) then h
      else find_subnet ip_address t;; 
  
  let add_address address list =
    list:=address::(!list)
  
  let remove_available_address subnet address =
    let address_filter f = (f<>address) in
    subnet.available_addresses:=List.filter address_filter !(subnet.available_addresses);;
  
  (*DHCP Options*)
  
  let rec parameter_request client_requests server_parameters = match client_requests with
    |[]->[]
    |(h::t) -> List.assoc h server_parameters :: (parameter_request t server_parameters);;

  let make_options_with_lease ~client_requests ~server_parameters ~serverIP ~lease_length ~message_type =
    let open Dhcpv4_option.Packet in
    (*let params = parameter_request ~c_requests:client requests ~s_parameters:parameters_list in*)
    { op = message_type; opts= [`Lease_time lease_length;`Server_identifier serverIP;`End]};;
    
  let make_options_without_lease ~client_requests ~server_parameters ~serverIP ~message_type =
    let open Dhcpv4_option.Packet in
    {op = message_type;opts = [`Server_identifier serverIP;`End]};;
   
  (*This function is ultimately responsible for all outward bound traffic from the server*)  
  let output_broadcast ?nak:(n=false) t ~xid ~ciaddr ~yiaddr ~siaddr ~giaddr ~chaddr ~flags ~options =
    let options = Dhcpv4_option.Packet.to_bytes options in
    let options_len = Bytes.length options in
    let total_len = options_len + sizeof_dhcp in
    let buf = Io_page.(to_cstruct (get 1)) in
    set_dhcp_op buf (mode_to_int BootReply); (*All server messages use the op BOOTREPLY*)
    set_dhcp_htype buf 1; (*Default to ethernet, TODO: implement other hardware types*)
    set_dhcp_hlen buf 6; (*Hardware address length, defaulted to ethernet*)
    set_dhcp_hops buf 0; (*Hops is used by relay agents, server always initialises it to 0*)
    set_dhcp_xid buf xid; (*Transaction id, generated by client*)
    set_dhcp_secs buf 0; (*Secs is always 0 in a server message*)
    set_dhcp_flags buf flags; (*Flags field. Server always sends back the flags received from the client*)
    set_dhcp_ciaddr buf 0l; (*client IP address, server is allowed to always set this to 0, but it can be set to the passed ciaddr in ACKs*)
    set_dhcp_yiaddr buf (Ipaddr.V4.to_int32 yiaddr); (*'your' ip address, the address being offered/assigned to the client*)
    set_dhcp_siaddr buf (Ipaddr.V4.to_int32 siaddr); (*server IP address. This should be the next server in the bootstrap sequence, which may not be this one*)
    set_dhcp_giaddr buf (Ipaddr.V4.to_int32 giaddr); (*gateway IP address, the IP address of the previous BOOTP relay the client package passed through, 0 if none*)
    (* TODO add a pad/fill function in cstruct *)
    set_dhcp_chaddr chaddr 0 buf; (*Client hardware address. TODO: ensure this is being passed correctly...*)
    set_dhcp_sname (Bytes.make 64 '\000') 0 buf; (*server name, TODO: find out how to set this in dhcpd*)
    set_dhcp_file (Bytes.make 128 '\000') 0 buf;
    set_dhcp_cookie buf 0x63825363l;
    Cstruct.blit_from_string options 0 buf sizeof_dhcp options_len;
    let dest_ip_address =
      if(giaddr <> Ipaddr.V4.unspecified) then giaddr (*giaddr set: forward onto the correct BOOTP relay*) (*see RFC 2131 page 22 for more info on dest address selection*)
      else if n then Ipaddr.V4.broadcast (*Naks must be broadcast unless they are sent to the giaddr.*)
      else if (ciaddr <> Ipaddr.V4.unspecified) then ciaddr (*giaddr not set, ciaddr set: unicast to ciaddr*)
      else if (flags = 0) then yiaddr (*ciaddr and giaddr not set, broadcast flag not set: unicast to yiaddr.
      Problem: currently only 1 DHCP flag is used, so this is valid, if other flags start seeing use, this will no longer work*)
      else Ipaddr.V4.broadcast (*ciaddr and giaddr not set, broadcast flag set.*)
    in
    let buf = Cstruct.set_len buf (sizeof_dhcp + options_len) in
      Console.log_s t.c (sprintf "Sending DHCP packet (length %d)" total_len)
      >>= fun () ->
        Stack.UDPV4.write ~dest_ip: dest_ip_address ~source_port:67 ~dest_port:68 (Stack.udpv4 t.stack) buf;; (*DHCP uses port 67 for the server and 68 for the client*)
  
  (*unwrap DHCP packet, case split depending on the contents*)
  let input t ~src ~dst ~src_port:_ buf = (*lots of duplication with client, need to combine into one unit*)
    let ciaddr = Ipaddr.V4.of_int32 (get_dhcp_ciaddr buf) in
    let yiaddr = Ipaddr.V4.of_int32 (get_dhcp_yiaddr buf) in
    let siaddr = Ipaddr.V4.of_int32 (get_dhcp_siaddr buf) in
    let giaddr = Ipaddr.V4.of_int32 (get_dhcp_giaddr buf) in
    let xid = get_dhcp_xid buf in
    let of_byte x =
      Printf.sprintf "%02x" (Char.code x) in
    let chaddr_to_string x =
      let chaddr_size = (Bytes.length x) in
      let dst_buffer = (Bytes.make (chaddr_size * 2) '\000') in
        for i = 0 to (chaddr_size - 1) do
          let thischar = of_byte x.[i] in
            Bytes.set dst_buffer (i*2) (Bytes.get thischar 0);
            Bytes.set dst_buffer ((i*2)+1) (Bytes.get thischar 1)
          done;
          dst_buffer
    in
    let chaddr = (chaddr_to_string) (copy_dhcp_chaddr buf) in
    let flags = get_dhcp_flags buf in
    let options = Cstruct.(copy buf sizeof_dhcp (len buf - sizeof_dhcp)) in (*need to look inside the options packet to see if server id is set: this distinguishes a request from a renewal*)
    let packet = Dhcpv4_option.Packet.of_bytes options in
    Lwt_list.iter_s (Console.log_s t.c)
      [ "DHCP response:";
        sprintf "input ciaddr %s yiaddr %s" (Ipaddr.V4.to_string ciaddr) (Ipaddr.V4.to_string yiaddr);
        sprintf "siaddr %s giaddr %s" (Ipaddr.V4.to_string siaddr) (Ipaddr.V4.to_string giaddr);
        sprintf "chaddr %s sname %s file %s" (chaddr) (copy_dhcp_sname buf) (copy_dhcp_file buf)]
    >>= fun () ->
    let open Dhcpv4_option.Packet in
    let client_identifier = match find packet (function `Client_id id -> Some id |_ -> None) with (*If a client ID is explcitly provided, use it, else default to using client hardware address for id*)
      |None -> chaddr
      |Some id-> Console.log t.c (sprintf "Client identifer set to %s" id);id
    in
    let client_subnet = if (giaddr = Ipaddr.V4.unspecified) then t.server_subnet  
      else find_subnet giaddr (t.subnets) (*the client is not on the same subnet, the packet has travelled via a BOOTP relay (with address giaddr). Use the subnet that contains the relay*)     
    in
    let lease_length = match find packet (function `Lease_time requested_lease -> Some requested_lease |_ -> None) with
      |None -> client_subnet.default_lease_length
      |Some requested_lease-> Int32.of_int(min (Int32.to_int requested_lease) (Int32.to_int (client_subnet.max_lease_length)))
    in
    let client_requests = match find packet (function `Parameter_request params -> Some params |_ -> None) with
      |None -> []
      |Some params -> params
    in
    let serverIP = client_subnet.serverIP in
    let server_parameters = client_subnet.parameters in
    match packet.op with
      |`Discover -> (* TODO: should probe address via ICMP here, and ensure that it's actually free, and try a new one if not*)
        let reserved_ip_address = match find packet (function `Requested_ip requested_address -> Some requested_address | _ -> None) with (*check whether the client has requested a specific address, and if possible reserve it for them*)
          |None-> List.hd !(client_subnet.available_addresses)
          |Some requested_address ->
            if List.mem requested_address !(client_subnet.available_addresses) then requested_address
            else List.hd !(client_subnet.available_addresses)
        in
        Console.log t.c (sprintf "Packet is a discover, currently %d reserved addresses in this subnet" (List.length !(client_subnet.reserved_addresses)));
        Console.log t.c (sprintf "Reserving %s for this client" (Ipaddr.V4.to_string reserved_ip_address));
        let new_reservation = client_identifier,{reserved_ip_address;xid;reservation_timestamp=Clock.time()} in
        add_address new_reservation client_subnet.reserved_addresses;
        Console.log t.c (sprintf "Now %d reserved addresses" (List.length !(client_subnet.reserved_addresses)));
        remove_available_address client_subnet reserved_ip_address;
        let options = make_options_with_lease ~client_requests: client_requests ~server_parameters:server_parameters ~serverIP: serverIP ~lease_length:lease_length ~message_type:`Offer in
        (*send DHCP Offer*)
        output_broadcast t ~xid:xid ~ciaddr:ciaddr ~yiaddr:reserved_ip_address ~siaddr:serverIP ~giaddr:giaddr ~chaddr:chaddr ~flags:flags ~options:options;
      |`Request ->
        Console.log t.c (sprintf "Packet is a request");
        (match (find packet(function `Server_identifier id ->Some id |_ -> None)) with
          |Some id -> (*This is a true request, client has no IP address*)
            let server_identifier = id
            in
            Console.log t.c (sprintf "True request");
            if ((List.mem server_identifier (t.serverIPs)) && ((List.assoc client_identifier !(client_subnet.reserved_addresses)).xid=xid)) then ( (*the client is requesting the IP address, this is not a renewal. Need error handling*)
              let ip_address = (List.assoc client_identifier !(client_subnet.reserved_addresses)).reserved_ip_address in
              let new_reservation = client_identifier,{ip_address;lease_length;lease_timestamp=Clock.time()} in
              add_address new_reservation client_subnet.in_use_addresses;
              client_subnet.reserved_addresses:=List.remove_assoc client_identifier !(client_subnet.reserved_addresses);
              let options = make_options_with_lease ~client_requests: client_requests ~server_parameters:server_parameters ~serverIP: serverIP ~lease_length:lease_length ~message_type:`Ack in
              output_broadcast t ~xid:xid ~ciaddr:ciaddr ~yiaddr:ip_address ~siaddr:serverIP ~giaddr:giaddr ~chaddr:chaddr ~flags:flags ~options:options;
            )
            else Lwt.return_unit; (*either the request is for a different server or the xid doesn't match the server's most recent transaction with that client*)
          |None -> (*this is a renewal, rebinding or init_reboot.*)
            if (ciaddr = Ipaddr.V4.unspecified) then (*client in init-reboot*)
              let requested_IP = match find packet (function `Requested_ip ip -> Some ip |_ -> None) with
                |None -> raise (Error "init-reboot with no requested IP")
                |Some ip_address -> ip_address
              in
              if (List.mem requested_IP !(client_subnet.available_addresses)) then (*address is available, lease to client*)
                let new_reservation = client_identifier,{ip_address=requested_IP;lease_length=lease_length;lease_timestamp=Clock.time()} in
                add_address new_reservation client_subnet.in_use_addresses;
                remove_available_address client_subnet requested_IP;
                let options = make_options_with_lease ~client_requests: client_requests ~server_parameters:server_parameters ~serverIP: serverIP ~lease_length:lease_length ~message_type:`Ack in
                output_broadcast t ~xid:xid ~ciaddr:ciaddr ~yiaddr:requested_IP ~siaddr:serverIP ~giaddr:giaddr ~chaddr:chaddr ~flags:flags ~options:options;
              else (*address is not available, either because it's taken or because it's not on this subnet send Nak*)
                let options = make_options_without_lease ~serverIP:serverIP ~message_type:`Nak ~client_requests: client_requests ~server_parameters:server_parameters in
                output_broadcast t ~xid:xid ~nak:true ~ciaddr:ciaddr ~yiaddr:(Ipaddr.V4.unspecified) ~siaddr:(Ipaddr.V4.unspecified) ~giaddr:giaddr ~chaddr:chaddr ~flags:flags ~options:options;
            else (*client in renew or rebind. TODO, can use the dst IP address in the function prototype to case split these*)
              if (List.mem dst t.serverIPs) then (*the packet was unicasted here, it's a renewal*)
                let new_reservation = client_identifier,{ip_address=ciaddr;lease_length=lease_length;lease_timestamp=Clock.time()} in
                (*delete previous record and create a new one. Currently, accept all renewals*)
                client_subnet.in_use_addresses:= List.remove_assoc client_identifier !(client_subnet.in_use_addresses);
                add_address new_reservation client_subnet.in_use_addresses;
                let options = make_options_with_lease ~client_requests: client_requests ~server_parameters:server_parameters ~serverIP: serverIP ~lease_length:lease_length ~message_type:`Ack in
                output_broadcast t ~xid:xid ~ciaddr:ciaddr ~yiaddr:ciaddr ~siaddr:serverIP ~giaddr:giaddr ~chaddr:chaddr ~flags:flags ~options:options;
              else if (dst = Ipaddr.V4.broadcast) then Lwt.return_unit(*the packet was multicasted here, it's a rebinding*)
              else Lwt.return_unit (*error case, this should never be used*)
            )
      |`Decline -> (*This means that the client has discovered that the offered IP address is in use, the server responds by reserving the address until a client explicitly releases it*)
        (try
          let ip_address = (List.assoc chaddr !(client_subnet.reserved_addresses)).reserved_ip_address in
          let new_reservation = "Unknown", {ip_address;lease_length=Int32.max_int;lease_timestamp=Clock.time()} in (*set lease to the maximum: this means it won't expire*)
          add_address new_reservation client_subnet.in_use_addresses; (*must notify network admin*)
          client_subnet.reserved_addresses:=List.remove_assoc client_identifier !(client_subnet.reserved_addresses);
          Lwt.return_unit;
        with
          |Not_found -> Lwt.return_unit;)
      |`Release -> (*this may give errors with duplicate packets, should wipe ALL entries*)
        let entry = client_identifier in
        Console.log t.c (sprintf "Packet is a release");
        if (List.mem_assoc entry !(client_subnet.in_use_addresses)) then (
          add_address ciaddr client_subnet.available_addresses;
          client_subnet.in_use_addresses:=List.remove_assoc entry !(client_subnet.in_use_addresses));
          Lwt.return_unit;
      |`Inform ->
        let options = make_options_without_lease ~client_requests:client_requests ~serverIP:serverIP ~server_parameters:server_parameters ~message_type:`Ack in
        output_broadcast t ~xid:xid ~ciaddr:ciaddr ~yiaddr:yiaddr ~siaddr:serverIP ~giaddr:giaddr ~chaddr:chaddr ~flags:flags ~options:options;
      | _ -> Lwt.return_unit;; (*this is a packet meant for a client*)
      
  let rec garbage_collect t collection_interval =
    Console.log t.c (sprintf "GC running!");
    let rec gc_reserved =function
      |[] -> []
      |h::t -> if (Clock.time()-.(snd h).reservation_timestamp > collection_interval) then (gc_reserved t)
        else (gc_reserved t)
    in
    let rec gc_in_use = function
      |[] -> []
      |h::t -> 
        let lease = Int32.to_int((snd h).lease_length) in
        if (lease != 0xffffffff && (int_of_float(Clock.time()-.(snd h).lease_timestamp) > lease)) then gc_in_use t else h::(gc_in_use t)
    in
    let rec gc = function
    |[]-> (Time.sleep collection_interval)>>=fun()->(garbage_collect t collection_interval)
    |subnet::tail -> subnet.reserved_addresses:=(gc_reserved !(subnet.reserved_addresses));(subnet.in_use_addresses:=(gc_in_use !(subnet.in_use_addresses)));gc tail
    in
    gc (t.subnets);;

  let serverThread t =
    Stack.listen_udpv4 (t.stack) 67 (input t);
    Lwt.return_unit;;
  
  let get = function (*replace with dedictaed function*)
  |Some x->x
  |None -> raise (Error "Undefined parameter");;
  
  let start ~c ~clock ~stack =
    let serverIPs = Stack.IPV4.get_ip (Stack.ipv4 stack) in
    let open Dhcp_serverv4_config_parser in 
    let parameters = Dhcp_serverv4_config_parser.read_DHCP_config in (*read parameters from /etc/dhcpd.conf*)
    (*extract global parameters*)
    let global_default_lease  = !(parameters.globals.default_lease_length) in
    let global_max_lease = !(parameters.globals.max_lease_length) in
    let global_parameters = !(parameters.globals.parameters) in
    let rec extract_subnets = function
    |[]-> []
    |(subnet,netmask,subnet_parameters)::t ->
      let parameters = (`Subnet_mask netmask)::(!(subnet_parameters.parameters)) in 
      let scope_bottom = get !(subnet_parameters.scope_bottom) in
      let scope_top = get !(subnet_parameters.scope_top) in
      let reserved_addresses = ref [] in
      let in_use_addresses= ref [] in
      let available_addresses = ref (list_gen (scope_bottom,scope_top)) in
      let max_lease_length =
        let subnet_lease = !(subnet_parameters.max_lease_length) in
        match subnet_lease with
        |Some lease -> lease
        |None -> (*no specific lease length provided for subnet, try global length*)
          match global_max_lease with
          |Some lease -> lease
          |None -> raise (Error ("No max lease length for subnet "^(Ipaddr.V4.to_string subnet)))
      in
      let default_lease_length =
        let subnet_lease = !(subnet_parameters.default_lease_length) in
        match subnet_lease with
        |Some lease -> lease
        |None ->
          match global_default_lease with
          |Some lease -> lease
          |None -> raise (Error ("No default lease length for subnet "^(Ipaddr.V4.to_string subnet)))
      in
      let serverIP=(List.hd serverIPs) in (*RFC 2131 states that the server SHOULD adjust the IP address it provides according to the location of the client (page 22 paragraph 2).
      It MUST pick one that it believes is reachable by the client. TODO: adjust IP according to client location*)
      let subnet_record = {subnet;netmask;parameters;max_lease_length;default_lease_length;reserved_addresses;in_use_addresses;available_addresses;serverIP} in
      subnet_record::(extract_subnets t)
    in
    let subnets = extract_subnets !(parameters.subnets) in
    let server_subnet = (*assumption:all of the server's IPs are on the same subnet*)
      let test_IP = List.hd (serverIPs) in
      find_subnet test_IP subnets
    in
    let t = {c;stack;server_subnet;serverIPs;subnets;global_parameters} in
    Lwt.join([serverThread t; garbage_collect t 60.0]);; 
end