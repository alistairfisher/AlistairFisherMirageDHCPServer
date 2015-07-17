(*Initial DHCP- need to migrate to IRMIN, dynamic allocation only,no additional information (DHCPInform),server IP is always this server, no renewals or rebinding cases, no init-reboot case,
,no address selection based on giaddr, no probing before reusing address, customisation of hardware options, reading params from config file, account for clock drift, can only serve 1 subnet*)

(*TODO: look closely at giaddr, requested IP in DHCPRequest*)

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
    ip_address: Ipaddr.V4.t;
    xid: Cstruct.uint32;
    reservation_timestamp: float;
  }
    
  type in_use_address = { (*use this to store client info, clientID/IPaddr is a key*)
    lease_length:int32;
    lease_timestamp:float; 
  }
    
  type clientID = {
    identifier: string;
    client_ip_address: Ipaddr.V4.t;
  }
    
  type t = {
    c: Console.t;
    stack: Stack.t;
    reserved_addresses:(string*reserved_address) list ref;
    in_use_addresses:(clientID*in_use_address) list ref;
    available_addresses: Ipaddr.V4.t list ref;
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
    
  let rec list_gen(bottom,top) = (*TODO: need to insert into main dhcp function*)
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
    
  let make_options_no_lease ~client_requests ~server_parameters ~serverIP ~message_type =
    let open Dhcpv4_option.Packet in
    {op = message_type;opts = [`Server_identifier serverIP;`End]};;
    
  let output_broadcast t ~xid ~ciaddr ~yiaddr ~siaddr ~giaddr ~secs ~chaddr ~flags ~options =
    let options = Dhcpv4_option.Packet.to_bytes options in
    let options_len = Bytes.length options in
    let total_len = options_len + sizeof_dhcp in
    let buf = Io_page.(to_cstruct (get 1)) in
    set_dhcp_op buf (mode_to_int BootReply);
    set_dhcp_htype buf 1;
    set_dhcp_hlen buf 6;
    set_dhcp_hops buf 0;
    set_dhcp_xid buf xid;
    set_dhcp_secs buf secs;
    set_dhcp_flags buf flags;
    set_dhcp_ciaddr buf 0l;
    set_dhcp_yiaddr buf (Ipaddr.V4.to_int32 yiaddr);
    set_dhcp_siaddr buf (Ipaddr.V4.to_int32 siaddr);
    set_dhcp_giaddr buf (Ipaddr.V4.to_int32 giaddr);
    (* TODO add a pad/fill function in cstruct *)
    set_dhcp_chaddr chaddr 0 buf; (*TODO: check this*)
    set_dhcp_sname (Bytes.make 64 '\000') 0 buf; (*check these 2*)
    set_dhcp_file (Bytes.make 128 '\000') 0 buf;
    set_dhcp_cookie buf 0x63825363l;
    Cstruct.blit_from_string options 0 buf sizeof_dhcp options_len;
    let dest_ip_address = match flags with 
      |0 -> yiaddr (*this is not future proof: currently only 1 flag is used so yiaddr is used iff flags = 0, this may change in the future*)
      |_ -> Ipaddr.V4.broadcast
    in
    let buf = Cstruct.set_len buf (sizeof_dhcp + options_len) in
      Console.log_s t.c (sprintf "Sending DHCP packet (length %d)" total_len)
      >>= fun () ->
        Stack.UDPV4.write ~dest_ip: dest_ip_address ~source_port:67 ~dest_port:68 (Stack.udpv4 t.stack) buf;;
  
  let add_address address list = 
    list:=address::(!list)
  
  let remove_available_address t address =
    let address_filter f = (f=address) in
    t.available_addresses:=List.filter address_filter !(t.available_addresses);;
  
  (*unwrap DHCP packet, case split depending on the contents*)
  let input t ~serverIP ~default_lease ~max_lease ~server_parameters ~src:_ ~dst:_ ~src_port:_ buf = (*lots of duplication with client, need to combine into one unit*)
    let ciaddr = Ipaddr.V4.of_int32 (get_dhcp_ciaddr buf) in
    let yiaddr = Ipaddr.V4.of_int32 (get_dhcp_yiaddr buf) in
    let siaddr = Ipaddr.V4.of_int32 (get_dhcp_siaddr buf) in
    let giaddr = Ipaddr.V4.of_int32 (get_dhcp_giaddr buf) in
    let secs = get_dhcp_secs buf in
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
    let client_identifier = match find packet (function `Client_id id -> Some id |_ -> None) with
      |None -> chaddr
      |Some id-> Console.log t.c (sprintf "Client identifer set to %s" id);id
    in
    let lease_length = match find packet (function `Lease_time requested_lease -> Some requested_lease |_ -> None) with
      |None -> default_lease
      |Some requested_lease-> Int32.of_int(min (Int32.to_int requested_lease) (Int32.to_int max_lease))
    in
    let client_requests = match find packet (function `Parameter_request params -> Some params |_ -> None) with
      |None -> []
      |Some params -> params
    in
    match packet.op with
      |`Discover ->
        let address = match find packet (function `Requested_ip requested_address -> Some requested_address | _ -> None) with
          |None-> List.hd !(t.available_addresses)
          |Some requested_address ->
            if List.mem requested_address !(t.available_addresses) then requested_address
            else List.hd !(t.available_addresses)
        in
        Console.log t.c (sprintf "Packet is a discover, currently %d reserved addresses" (List.length !(t.reserved_addresses)));
        Console.log t.c (sprintf "Allocating %s" (Ipaddr.V4.to_string address));
        let new_reservation = client_identifier,{ip_address=address;xid=xid;reservation_timestamp=Clock.time()} in
        add_address new_reservation t.reserved_addresses;
        Console.log t.c (sprintf "Now %d reserved addresses" (List.length !(t.reserved_addresses)));
        remove_available_address t address;
        let options = make_options_with_lease ~client_requests: client_requests ~server_parameters:server_parameters ~serverIP: serverIP ~lease_length:lease_length ~message_type:`Offer in
        (*send DHCP Offer*)
        output_broadcast t ~xid:xid ~ciaddr:0 ~yiaddr:address ~siaddr:serverIP ~giaddr:giaddr ~secs:secs ~chaddr:chaddr ~flags:flags ~options:options;
      |`Request ->
        Console.log t.c (sprintf "Packet is a request");
        (match (find packet(function `Server_identifier id ->Some id |_ -> None)) with
          |Some id -> (*This is a true request, client has no IP address*)
            let server_identifier = id
            in
            Console.log t.c (sprintf "True request");
            if (server_identifier=serverIP && ((List.assoc client_identifier !(t.reserved_addresses)).xid=xid)) then ( (*the client is requesting the IP address, this is not a renewal. Need error handling*)
              let address = (List.assoc client_identifier !(t.reserved_addresses)).ip_address in
              let new_reservation = {identifier=client_identifier;client_ip_address=address},{lease_length=lease_length;lease_timestamp=Clock.time()} in
              add_address new_reservation t.in_use_addresses;
              t.reserved_addresses:=List.remove_assoc client_identifier !(t.reserved_addresses);
              let options = make_options_with_lease ~client_requests: client_requests ~server_parameters:server_parameters ~serverIP: serverIP ~lease_length:lease_length ~message_type:`Ack in
              output_broadcast t ~xid:xid ~ciaddr:ciaddr ~yiaddr:address ~siaddr:serverIP ~giaddr:giaddr ~secs:secs ~chaddr:chaddr ~flags:flags ~options:options;
            )
            else Lwt.return_unit;
          |None -> (*this is a renewal, rebinding or init_reboot*)
            if (ciaddr = Ipaddr.V4.unspecified) then (*client in init-reboot*)
              let requested_IP = match find packet (function `Requested_ip ip -> Some ip |_ -> None) with
                |None -> raise Error "init-reboot with no requested IP"
                |Some ip -> ip
              in
              if (List.mem requested_IP !(t.available_addresses)) then (*address is available, lease to client*)
                let new_reservation = {identifier=client_identifier;client_ip_address=requested_IP},{lease_length=lease_length;lease_timestamp=Clock.time()} in
                add_address new_reservation t.in_use_addresses;
                remove_available_address t requested_IP;
                let options = make_options_with_lease ~client_requests: client_requests ~server_parameters:server_parameters ~serverIP: serverIP ~lease_length:lease_length ~message_type:`Ack in
                output_broadcast t ~xid:xid ~ciaddr:ciaddr ~yiaddr:requested_IP ~siaddr:serverIP ~giaddr:giaddr ~secs:secs ~chaddr:chaddr ~flags:flags ~options:options;
              else (*address is not available, send Nak*)
                let options = make_options_without_lease ~serverIP:serverIP ~message_type:`Nak in
                output_broadcast t ~xid:xid ~ciaddr:(Ipaddr.V4.unspecified) ~yiaddr:(Ipaddr.V4.unspecified) ~siaddr:(Ipaddr.V4.unspecified) ~giaddr:giaddr ~secs:secs ~chaddr:chaddr ~flags:flags ~options:options;
            else (*client in renew or rebind*)
              Lwt.return_unit;)
      |`Decline ->
        (try
          let address = (List.assoc chaddr !(t.reserved_addresses)).ip_address in
          let new_reservation = {identifier="Unknown";client_ip_address=address}, {lease_length=Int32.max_int;lease_timestamp=Clock.time()} in
          add_address new_reservation t.in_use_addresses; (*must notify network admin*)
          t.reserved_addresses:=List.remove_assoc chaddr !(t.reserved_addresses);
          Lwt.return_unit;
        with
          |Not_found -> Lwt.return_unit;)
      |`Release -> (*this may give errors with duplicate packets, should wipe ALL entries*)
        let entry = {identifier=client_identifier;client_ip_address=ciaddr} in
        Console.log t.c (sprintf "Packet is a release");
        if (List.mem_assoc entry !(t.in_use_addresses)) then (
          add_address ciaddr t.available_addresses;
          t.in_use_addresses:=List.remove_assoc entry !(t.in_use_addresses));
          Lwt.return_unit;
      |`Inform ->
        let options = make_options_no_lease ~client_requests:client_requests ~serverIP:serverIP ~server_parameters:server_parameters ~message_type:`Ack in
        output_broadcast t ~xid:xid ~ciaddr:ciaddr ~yiaddr:yiaddr ~siaddr:serverIP ~giaddr:giaddr ~secs:secs ~chaddr:chaddr ~flags:flags ~options:options;
      | _ ->Lwt.return_unit;; (*this is a packet meant for a client*)
      
  let rec garbage_collect t collection_interval=
    Console.log t.c (sprintf "GC running!");
    let rec gc_reserved l = match (l) with
      |[] -> []
      |h::t -> if (Clock.time()-.(snd h).reservation_timestamp > collection_interval) then (gc_reserved t)
        else (gc_reserved t)
    in
    let rec gc_in_use = function
      |[] -> []
      |h::t -> 
        let lease = Int32.to_int((snd h).lease_length) in
        if (lease != 0xffffffff && (int_of_float(Clock.time()-.(snd h).lease_timestamp) > lease)) then gc_in_use t else h::(gc_in_use t)
    in OS.Time.sleep(collection_interval)>>=fun()->(t.reserved_addresses:=(gc_reserved !(t.reserved_addresses)));(t.in_use_addresses:=(gc_in_use !(t.in_use_addresses)));
      garbage_collect t collection_interval;;

  let rec serverThread t default_lease max_lease serverIP server_parameters=
    Stack.listen_udpv4 (t.stack) 67 (input t ~serverIP:serverIP ~default_lease:default_lease ~max_lease:max_lease ~server_parameters:server_parameters);
    serverThread t lease_length serverIP server_parameters;;
    
  let start ~c ~clock ~stack= (*note: lease time is in seconds. 0xffffffff is reserved for infinity*)
    let parameters = Dhcp_serverv4_config_parser in
    let scopebottom = parameters.globals.scope_bottom in
    let scopetop = parameters.globals.scope_top in
    let default_lease  = parameters.globals.default_lease_length in
    let max_lease = parameters.globals.max_lease_length in
    let serverIP = Stack.IPV4.get_ipv4 (Stack.ipv4 t.stack) in
    let server_parameters = [] in
    let reserved_addresses = ref [] in
    let in_use_addresses= ref [] in
    let available_addresses = ref (list_gen (scopebottom,scopetop)) in
    let t = {c;stack;reserved_addresses;in_use_addresses;available_addresses} in
    Lwt.join([serverThread t default_lease max_lease serverIP server_parameters;garbage_collect t 60.0]);; 
end