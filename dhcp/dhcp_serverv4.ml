(*Initial DHCP- need to hashtables, dynamic allocation only,no additional information (DHCPInform),server IP is always this server, no renewals or rebinding cases,
no probing before reusing address,no customisation of hardware options, reading params from config file (WIP), account for clock drift, can only serve 1 subnet*)

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
    
  (*TODO: use a new type for client ID to differentiate explicit ID from hardware address, and need to case split on type*)  
    
  type clientID = string;; (*According to RFC 2131, this should be the client's hardware address unless an explicit identifier is provided. The RFC states that the ID must be unique within the subnet, but the onus is on the client to ensure this
    if it chooses to use an explicit identifier: the server shouldn't need to check it for uniqueness. The full identifier is the combination of subnet and identifier, but the subnet is implicit in this implementation*)
  
  (*TODO: supplement this with a server IP that should be used for all clients on this subnet*)
  
  type subnet = {
    subnet: Ipaddr.V4.t;
    netmask: Ipaddr.V4.t;
    parameters: Dhcpv4_option.t list;
    max_lease_length: int32 option;
    default_lease_length: int32 option;
    reserved_addresses:(clientID*reserved_address) list ref;
    in_use_addresses:(clientID*in_use_address) list ref;
    available_addresses: Ipaddr.V4.t list ref;
    serverIP: Ipaddr.V4.t; (*The IP address of the interface that should be used to communicate with hosts on this subnet*)
  }
    
  type t = {
    c: Console.t;
    stack: Stack.t;
    server_subnet: Ipaddr.V4.t;
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
    
  let rec list_gen(bottom,top) =
    let a = Ipaddr.V4.to_int32 bottom in
    let b = Ipaddr.V4.to_int32 top in
    if a>b then []
    else bottom::list_gen(Ipaddr.V4.of_int32(Int32.add a Int32.one),top);;
  
  let rec parameter_request c_requests s_parameters = match c_requests with
    |[]->[]
    |(h::t) -> List.assoc h s_parameters :: (parameter_request t s_parameters);;

  let make_options_with_lease ~client_requests ~server_parameters ~serverIP ~lease_length ~message_type =
    let open Dhcpv4_option.Packet in
    (*let params = parameter_request ~c_requests:client requests ~s_parameters:parameters_list in*)
    { op = message_type; opts= [`Lease_time lease_length;`Server_identifier serverIP;`End]};;
    
  let make_options_without_lease ~client_requests ~server_parameters ~serverIP ~message_type =
    let open Dhcpv4_option.Packet in
    {op = message_type;opts = [`Server_identifier serverIP;`End]};;
   
  let rec find_subnet ip_address subnets =
    let routing_prefix netmask ip_address=
      let open Ipaddr.V4 in
      of_int32(Int32.logand((to_int32 (address)) (to_int32 (netmask))))
    in
    let compare_address_to_subnet subnet =
      let prefix = routing_prefix (subnet.netmask) in
      (prefix subnet.subnet)=(prefix ip_address)
    in
    match subnets with
    |[] -> raise (Error "Server subnet not found")
    |h::t ->
      if (compare_address_to_subnet h) then h
      else find_subnet ip_address t;; 
  
   
  let output_broadcast t ~xid ~ciaddr ~yiaddr ~siaddr ~giaddr ~secs ~chaddr ~flags ~options ?nak:(n=false) =
    let options = Dhcpv4_option.Packet.to_bytes options in
    let options_len = Bytes.length options in
    let total_len = options_len + sizeof_dhcp in
    let buf = Io_page.(to_cstruct (get 1)) in
    set_dhcp_op buf (mode_to_int BootReply); (*All server messages use the op BOOTREPLY*)
    set_dhcp_htype buf 1; (*Default to ethernet, TODO: implement other hardware types*)
    set_dhcp_hlen buf 6; (*Hardware address length, defaulted to ethernet*)
    set_dhcp_hops buf 0; (*Hops is used by relay agents, server always initialises it to 0*)
    set_dhcp_xid buf xid; (*Transaction id, generated by client*)
    set_dhcp_secs buf secs; (*Always 0 in a server message*)
    set_dhcp_flags buf flags; (*Flags field. Server always sends back the flags received from the client*)
    set_dhcp_ciaddr buf 0l; (*client IP address, server is allowed to always set this to 0*)
    set_dhcp_yiaddr buf (Ipaddr.V4.to_int32 yiaddr); (*'your' ip address, the address being offered/assigned to the client*)
    set_dhcp_siaddr buf (Ipaddr.V4.to_int32 siaddr); (*server IP address. This should be the next server in the bootstrap sequence, which may not be this one*)
    set_dhcp_giaddr buf (Ipaddr.V4.to_int32 giaddr); (*gateway IP address, the IP address of the previous BOOTP relay the client package passed through, 0 if none*)
    (* TODO add a pad/fill function in cstruct *)
    set_dhcp_chaddr chaddr 0 buf; (*Client hardware address. TODO: ensure this is being passed correctly...*)
    set_dhcp_sname (Bytes.make 64 '\000') 0 buf; (*server name, TODO: find out how to set this in dhcpd*)
    set_dhcp_file (Bytes.make 128 '\000') 0 buf;
    set_dhcp_cookie buf 0x63825363l;
    Cstruct.blit_from_string options 0 buf sizeof_dhcp options_len;
    let dest_ip_address = match flags,giaddr,ciaddr,n with
      |0,Ipaddr.V4.unspecified,Ipaddr.V4.unspecified,false -> yiaddr (*Broadcast flag, giaddr and ciaddr all not set: unicast to yiaddr*)
      |_,Ipaddr.V4.unspecified,Ipaddr.V4.unspecified,false -> Ipaddr.V4.broadcast (*giaddr and ciaddr not set, broadcast flag set: broadcast*)
      |_,Ipaddr.V4.unspecified,addr,false -> addr (*giaddr not set, ciaddr set: unicast to ciaddr*)
      |_,Ipaddr.V4.unspecified,_,true -> Ipaddr.V4.broadcast (*used for Naks: Naks must be broadcast unless they are sent to the giaddr.*)
      |_,_,_,_ -> giaddr (*giaddr set: forward onto the correct BOOTP relay*) (*see RFC 2131 page 22 for more info*)
    in
    let buf = Cstruct.set_len buf (sizeof_dhcp + options_len) in
      Console.log_s t.c (sprintf "Sending DHCP packet (length %d)" total_len)
      >>= fun () ->
        Stack.UDPV4.write ~dest_ip: dest_ip_address ~source_port:67 ~dest_port:68 (Stack.udpv4 t.stack) buf;;
  
  let add_address address list = 
    list:=address::(!list)
  
  let remove_available_address subnet address =
    let address_filter f = (f<>address) in
    subnet.available_addresses:=List.filter address_filter !(subnet.available_addresses);;
  
  (*unwrap DHCP packet, case split depending on the contents*)
  let input t ~src:_ ~dst:_ ~src_port:_ buf = (*lots of duplication with client, need to combine into one unit*)
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
    let unspecified_address = Ipaddr.V4.unspecified in
    let client_subnet = match giaddr with
    |unspecified_address -> (*the client is on the same subnet as the server*)
      t.server_subnet  
      |specified_address -> find_subnet specified_address (t.subnets) (*the client is not on the same subnet, the packet has travelled via a BOOTP relay (with address giaddr).
      Use the subnet that contains the relay*)
    in
    let lease_length = match find packet (function `Lease_time requested_lease -> Some requested_lease |_ -> None) with
      |None -> client_subnet.default_lease
      |Some requested_lease-> Int32.of_int(min (Int32.to_int requested_lease) (Int32.to_int (client_subnet.max_lease_length)))
    in
    let client_requests = match find packet (function `Parameter_request params -> Some params |_ -> None) with
      |None -> []
      |Some params -> params
    in
    let serverIP = client_subnet.serverIP in
    let server_parameters = client_subnet.parameters in
    match packet.op with
      |`Discover -> (*should probe address via ICMP here, and ensure that it's actually free, and try a new one if not*)
        let reserved_ip_address = match find packet (function `Requested_ip requested_address -> Some requested_address | _ -> None) with (*check whether the client has requested a specific address, and if possible reserve it for them*)
          |None-> List.hd !(client_subnet.available_addresses)
          |Some requested_address ->
            if List.mem requested_address !(client_subnet.available_addresses) then requested_address
            else List.hd !(client_subnet.available_addresses)
        in
        Console.log t.c (sprintf "Packet is a discover, currently %d reserved addresses in this subnet" (List.length !(client_subnet.reserved_addresses)));
        Console.log t.c (sprintf "Reserving %s for this client" (Ipaddr.V4.to_string address));
        let new_reservation = client_identifier,{reserved_ip_address;xid;reservation_timestamp=Clock.time()} in
        add_address new_reservation client_subnet.reserved_addresses;
        Console.log t.c (sprintf "Now %d reserved addresses" (List.length !(client_subnet.reserved_addresses)));
        remove_available_address client_subnet reserved_ip_address;
        let options = make_options_with_lease ~client_requests: client_requests ~server_parameters:server_parameters ~serverIP: serverIP ~lease_length:lease_length ~message_type:`Offer in
        (*send DHCP Offer*)
        output_broadcast t ~xid:xid ~ciaddr:ciaddr ~yiaddr:address ~siaddr:serverIP ~giaddr:giaddr ~secs:secs ~chaddr:chaddr ~flags:flags ~options:options;
      |`Request ->
        Console.log t.c (sprintf "Packet is a request");
        (match (find packet(function `Server_identifier id ->Some id |_ -> None)) with
          |Some id -> (*This is a true request, client has no IP address*)
            let server_identifier = id
            in
            Console.log t.c (sprintf "True request");
            if ((List.mem server_identifier serverIPs) && ((List.assoc client_identifier !(t.reserved_addresses)).xid=xid)) then ( (*the client is requesting the IP address, this is not a renewal. Need error handling*)
              let address = (List.assoc client_identifier !(t.reserved_addresses)).ip_address in
              let new_reservation = client_identifier,{lease_length=lease_length;lease_timestamp=Clock.time()} in
              add_address new_reservation client_subnet.in_use_addresses;
              client_subnet.reserved_addresses:=List.remove_assoc client_identifier !(client_subnet.reserved_addresses);
              let options = make_options_with_lease ~client_requests: client_requests ~server_parameters:server_parameters ~serverIP: serverIP ~lease_length:lease_length ~message_type:`Ack in
              output_broadcast t ~xid:xid ~ciaddr:ciaddr ~yiaddr:address ~siaddr:serverIP ~giaddr:giaddr ~secs:secs ~chaddr:chaddr ~flags:flags ~options:options;
            )
            else Lwt.return_unit; (*either the request is for a different server or the xid doesn't match the server's most recent transaction with that client*)
          |None -> (*this is a renewal, rebinding or init_reboot. TODO: check whether requested IP is on the correct subnet*)
            if (ciaddr = Ipaddr.V4.unspecified) then (*client in init-reboot*)
              let requested_IP = match find packet (function `Requested_ip ip -> Some ip |_ -> None) with
                |None -> raise (Error "init-reboot with no requested IP")
                |Some ip -> ip
              in
              if (List.mem requested_IP !(client_subnet.available_addresses)) then (*address is available, lease to client*)
                let new_reservation = client_identifier,{lease_length=lease_length;lease_timestamp=Clock.time()} in
                add_address new_reservation client_subnet.in_use_addresses;
                remove_available_address subnet requested_IP;
                let options = make_options_with_lease ~client_requests: client_requests ~server_parameters:server_parameters ~serverIP: serverIP ~lease_length:lease_length ~message_type:`Ack in
                output_broadcast t ~xid:xid ~ciaddr:ciaddr ~yiaddr:requested_IP ~siaddr:serverIP ~giaddr:giaddr ~secs:secs ~chaddr:chaddr ~flags:flags ~options:options;
              else (*address is not available on this subnet, send Nak*)
                let options = make_options_without_lease ~serverIP:serverIP ~message_type:`Nak ~client_requests: client_requests ~server_parameters:server_parameters in
                output_broadcast t ~xid:xid ~ciaddr:ciaddr ~yiaddr:(Ipaddr.V4.unspecified) ~siaddr:(Ipaddr.V4.unspecified) ~giaddr:giaddr ~secs:secs ~chaddr:chaddr ~flags:flags ~options:options ~nak:true;
            else (*client in renew or rebind. TODO, can use the dst IP address in the function prototype to case split these*)
              Lwt.return_unit;)
      |`Decline -> (*This means that the client has discovered that the offered IP address is in use, the server responds by reserving the address until a client explicitly releases it*)
        (try
          let address = (List.assoc chaddr !(client_subnet.reserved_addresses)).ip_address in
          let new_reservation = {identifier="Unknown"}, {lease_length=Int32.max_int;lease_timestamp=Clock.time()} in
          add_address new_reservation client_subnet.in_use_addresses; (*must notify network admin*)
          client_subnet.reserved_addresses:=List.remove_assoc client_identifier !(client_subnet.reserved_addresses);
          Lwt.return_unit;
        with
          |Not_found -> Lwt.return_unit;)
      |`Release -> (*this may give errors with duplicate packets, should wipe ALL entries*)
        let entry = {identifier=client_identifier} in
        Console.log t.c (sprintf "Packet is a release");
        if (List.mem_assoc entry !(client_subnet.in_use_addresses)) then (
          add_address ciaddr client_subnet.available_addresses;
          client_subnet.in_use_addresses:=List.remove_assoc entry !(client_subnet.in_use_addresses));
          Lwt.return_unit;
      |`Inform ->
        let options = make_options_without_lease ~client_requests:client_requests ~serverIP:serverIP ~server_parameters:server_parameters ~message_type:`Ack in
        output_broadcast t ~xid:xid ~ciaddr:ciaddr ~yiaddr:yiaddr ~siaddr:serverIP ~giaddr:giaddr ~secs:secs ~chaddr:chaddr ~flags:flags ~options:options;
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
    in (Unix.sleep (int_of_float(collection_interval)));t.reserved_addresses:=(gc_reserved !(t.reserved_addresses));(t.in_use_addresses:=(gc_in_use !(t.in_use_addresses))); (*TODO: switch to time module.sleep*)
      (garbage_collect t collection_interval);;

  let rec serverThread t =
    Stack.listen_udpv4 (t.stack) 67 (input t);
    Lwt.return_unit;;
  
  let get = function
  |Some x->x
  |None -> raise (Error "Undefined parameter");;
  
  let start ~c ~clock ~stack =
    let serverIPs = Stack.IPV4.get_ip (Stack.ipv4 stack) in (*RFC 2131 states that the server SHOULD adjust the IP address it provides according to the location of the client (page 22 paragraph 2).
    It MUST pick one that it believes is reachable by the client. TODO: adjust IP according to client location*)    
    let parameters = Dhcp_serverv4_config_parser.read_DHCP_config in (*read parameters from /etc/dhcpd.conf*)
    (*extract global parameters*)
    let global_default_lease  = !(parameters.globals.default_lease_length) in
    let global_max_lease = !(parameters.globals.max_lease_length) in
    let global_parameters = parameters.globals in
    let rec extract_subnets = function
    |[]-> []
    |(subnet,netmask,subnet_parameters)::t ->
      let parameters = !(subnet_parameters.working_parameters.parameters) in
      let scope_bottom = get !(subnet_parameters.scope_bottom) in
      let scope_top = get !(subnet_parameters.scope_top) in
      let reserved_addresses = ref [] in
      let in_use_addresses= ref [] in
      let available_addresses = ref (list_gen (scopebottom,scopetop)) in
      let max_lease_length =
        let subnet_lease = !(subnet_parameters.max_lease_length) in
        match subnet_lease with
        |Some lease -> lease
        |None -> (*no specific lease length provided for subnet, try global length*)
          match global_max_lease with
          |Some lease -> lease
          |None -> raise (Error ("No max lease length for subnet"^(Ipaddr.V4.to_string subnet)))
      in
      let default_lease_length =
        let subnet_lease = !(subnet_parameters.default_lease_length) in
        match subnet_lease with
        |Some lease -> lease
        |None ->
          match global_default_lease with
          |Some lease -> lease
          |None -> raise (Error ("No default lease length for subnet"^(Ipaddr.V4.to_string subnet)))
      in
      let subnet_record = {subnet;netmask;parameters;max_lease_length;default_lease_length;reserved_addresses;in_use_addresses;available_addresses;serverIP=(List.hd serverIPs)} in
      subnet_record::(extract_subnets parameters.subnets)
    in
    let subnets = extract_subnets !(parameters.subnets) in
    let server_subnet = (*assumption:all of the server's IPs are on the same subnet*)
      let test_IP = List.hd (serverIPs) in
      find_subnet test_IP serverIPs
    in
    let t = {c;stack;server_subnet;subnets;global_parameters} in
    Lwt.join([serverThread t ;garbage_collect t 60.0]);; 
end