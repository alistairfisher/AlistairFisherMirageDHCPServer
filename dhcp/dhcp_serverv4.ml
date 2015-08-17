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
open Dhcpv4_util;;
open Dhcp_serverv4_data_structures;;

module Helper (Console:V1_LWT.CONSOLE)
  (Clock:V1.CLOCK) = struct
  
  exception Error of string;;
  
  (*Various helper functions*)
 
  let rec find_subnet ip_address subnets = (*Match an IP address to a subnet*)
    let routing_prefix netmask address= (*Find the routing prefix of address if it lived in the subnet with this netmask*)
      let open Ipaddr.V4 in
      let x = to_int32 address in
      let y = to_int32 netmask in
      of_int32(Int32.logand x y)
    in
    let compare_address_to_subnet subnet = (*Compare the supplied ip address to one subnet: they are the same if they have the same routing prefix*)
      let prefix = routing_prefix (subnet.netmask) in
      (prefix subnet.subnet)=(prefix ip_address)
    in
    match subnets with
    |[] -> raise (Error ("Subnet not found for address "^Ipaddr.V4.to_string(ip_address)))
    |h::t ->
      if (compare_address_to_subnet h) then h
      else find_subnet ip_address t;; 
  
  let rec remove_assoc_rec (key:string) list = (*remove all associations*)
    match list with
    |[] -> []
    |(a,b) :: t ->
      if a = key then remove_assoc_rec key t
      else (a,b) :: (remove_assoc_rec key t);;
  
  let change_address_state address state table =
    Dhcpv4_irmin.Table.Ops.add address state table
  
  let check_xid address table xid client_identifier = (*Check whether a request uses the correct xid for the reservation*)
    try
      let address_state = Dhcpv4_irmin.Table.Ops.find address table in
      address_state = (Reservation xid client_identifier)
    with
    | Not_found -> false;;
  
  let first_address subnet = List.hd !(subnet.available_addresses);;
  
  let find_reservation subnet client_identifier = 
      List.assoc client_identifier !(subnet.reservations);;

  let is_available address table = 
      try
        let address_state = Dhcpv4_irmin.Table.Ops.find address table in
        address_state = Available
      with
      | Not_found -> false
  
  let find_lease subnet client_identifier = 
      List.assoc client_identifier !(subnet.leases);;
  
  let exists_reservation subnet client_identifier = 
      List.mem_assoc client_identifier !(subnet.reservations);;
  
  let exists_lease subnet client_identifier = 
      List.mem_assoc client_identifier !(subnet.leases);;
  
  type t = {
    (*c: Console.t;*)
    server_subnet: subnet; (*A handle on the subnet that the server lives on, convenient for allocating addresses to hosts on the same subnet as the server*)
    serverIPs: Ipaddr.V4.t list;
    subnets: subnet list;
    global_parameters:  Dhcpv4_option.t list;
  }
  
  let server_construct_packet ?nak:(n=false) t ~xid ~ciaddr ~yiaddr ~siaddr ~giaddr ~chaddr ~flags ~options =
    let dest_ip_address =
      if(giaddr <> Ipaddr.V4.unspecified) then giaddr (*giaddr set: forward onto the correct BOOTP relay*) (*see RFC 2131 page 22 for more info on dest address selection*)
      else if n then Ipaddr.V4.broadcast (*Naks must be broadcast unless they are sent to the giaddr.*)
      else if (ciaddr <> Ipaddr.V4.unspecified) then ciaddr (*giaddr not set, ciaddr set: unicast to ciaddr*)
      else if (flags = 0) then yiaddr (*ciaddr and giaddr not set, broadcast flag not set: unicast to yiaddr.
      Problem: currently only 1 DHCP flag is used, so this is valid, if other flags start seeing use, this will no longer work*)
      else Ipaddr.V4.broadcast (*ciaddr and giaddr not set, broadcast flag set.*)
    in
    dhcp_packet_constructor ~op:BootReply ~xid:xid ~secs:0 ~flags:flags ~ciaddr:(Ipaddr.V4.unspecified) ~yiaddr:yiaddr ~siaddr:siaddr ~giaddr:giaddr ~chaddr:chaddr ~options:options
    ~dest:dest_ip_address
  
  (*unwrap DHCP packet, case split depending on the contents*)
  let parse_packet t ~src ~dst ~packet = (*lots of duplication with client, need to combine into one unit*)
    let ciaddr = packet.ciaddr in
    let yiaddr = packet.yiaddr in
    let giaddr = packet.giaddr in
    let xid    = packet.xid in
    let chaddr = packet.chaddr in
    let flags  = packet.flags in
    let packet = packet.options in
    (*Lwt_list.iter_s (Console.log_s t.c) TODO: put this back
      [ "DHCP response:";
        sprintf "input ciaddr %s yiaddr %s" (Ipaddr.V4.to_string ciaddr) (Ipaddr.V4.to_string yiaddr);
        sprintf "siaddr %s giaddr %s" (Ipaddr.V4.to_string siaddr) (Ipaddr.V4.to_string giaddr);
        sprintf "chaddr %s sname %s file %s" (chaddr) (copy_dhcp_sname buf) (copy_dhcp_file buf)]
    >>= fun () ->*)
    try
      let open Dhcpv4_option.Packet in
      let client_identifier = match find packet (function `Client_id id -> Some id |_ -> None) with (*If a client ID is explcitly provided, use it, else default to using client hardware address for id*)
        |None -> chaddr
        |Some id-> (*Console.log t.c (sprintf "Client identifer set to %s" id);*)id
      in
      let client_subnet =
        if (giaddr = Ipaddr.V4.unspecified) then (*either unicasted or on same subnet*)
          if dst = (Ipaddr.V4.broadcast) then t.server_subnet (*broadcasted -> on same subnet*)
          else find_subnet src (t.subnets) (*else unicasted, can use source address to find subnets*)
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
      let subnet_parameters = client_subnet.parameters in
      let open Dhcp_serverv4_options in
      match packet.op with
      |`Discover -> (* TODO: should probe address via ICMP here, and ensure that it's actually free, and try a new one if not*)
        let reserved_ip_address = match find packet (function `Requested_ip requested_address -> Some requested_address | _ -> None) with (*check whether the client has requested a specific address, and if possible reserve it for them*)
          |None-> first_address client_subnet
          |Some requested_address ->
            if (is_available requested_address client_subnet) then requested_address
            else first_address client_subnet
        in
        let new_table = change_address_state reserved_ip_address (Reserved xid client_identifier) in
        (*TODO: do something with this new table*)
        let options = make_options_with_lease ~client_requests: client_requests ~subnet_parameters:subnet_parameters ~global_parameters:t.global_parameters
        ~serverIP: serverIP ~lease_length:lease_length ~message_type:`Offer in
        (*send DHCP Offer*)
        Some (server_construct_packet t ~xid:xid ~ciaddr:ciaddr ~yiaddr:reserved_ip_address ~siaddr:serverIP ~giaddr:giaddr ~chaddr:chaddr ~flags:flags ~options:options);
      |`Request ->
        (match (find packet(function `Server_identifier id ->Some id |_ -> None)) with
          |Some server_identifier -> (*This is a response to an offer*)
            let requested_ip_address = match find packet (function `Requested_ip ip -> Some ip |_ -> None) with
              |None -> raise (Error "DHCP Request -  Select with no requested IP")
              |Some ip_address -> ip_address
            in
            if ((List.mem server_identifier (t.serverIPs)) && (check_xid requested_ip_address table xids client_identifier)) then (
              let table = change_address_state requested_ip_address (Active client_identifier) table in
              let options = make_options_with_lease ~client_requests: client_requests ~subnet_parameters:subnet_parameters ~global_parameters:t.global_parameters
              ~serverIP: serverIP ~lease_length:lease_length ~message_type:`Ack in
              Some (server_construct_packet t ~xid:xid ~ciaddr:ciaddr ~yiaddr:ip_address ~siaddr:serverIP ~giaddr:giaddr ~chaddr:chaddr ~flags:flags ~options:options);
            )
            else None; (*either the request is for a different server or the xid doesn't match the server's most recent transaction with that client*)
          |None -> (*this is a renewal, rebinding or init_reboot.*)
            if (ciaddr = Ipaddr.V4.unspecified) then (*client in init-reboot*)
              let requested_IP = match find packet (function `Requested_ip ip -> Some ip |_ -> None) with
                |None -> raise (Error "init-reboot with no requested IP")
                |Some ip_address -> ip_address
              if (is_available requested_IP table) then (*address is available, lease to client*)
                let table = change_address_state requested_IP table (Active client_identifier) in
                let options = make_options_with_lease ~client_requests: client_requests ~subnet_parameters:subnet_parameters ~global_parameters:t.global_parameters
                ~serverIP: serverIP ~lease_length:lease_length ~message_type:`Ack in
                Some (server_construct_packet t ~xid:xid ~ciaddr:(Ipaddr.V4.unspecified) ~yiaddr:requested_IP ~siaddr:serverIP ~giaddr:giaddr ~chaddr:chaddr ~flags:flags ~options:options);
              else (*address is not available, either because it's taken or because it's not on this subnet send Nak*)
                let options = make_options_without_lease ~serverIP:serverIP ~message_type:`Nak ~client_requests: client_requests
                ~subnet_parameters:subnet_parameters ~global_parameters:t.global_parameters in
                Some (server_construct_packet t ~xid:xid ~nak:true ~ciaddr:(Ipaddr.V4.unspecified) ~yiaddr:(Ipaddr.V4.unspecified) ~siaddr:(Ipaddr.V4.unspecified) ~giaddr:giaddr ~chaddr:chaddr ~flags:flags ~options:options);
            else (*client in renew or rebind.*)
              if (List.mem dst t.serverIPs) then (*the packet was unicasted here, it's a renewal*)
                (*Note: RFC 2131 states that the server should trust the client here, despite potential security issues*)
                change_address_state 
                (*delete previous record and create a new one. Currently, accept all renewals*)
                remove_lease client_subnet client_identifier;
                add_address new_reservation client_subnet.leases;
                let options = make_options_with_lease ~client_requests: client_requests ~subnet_parameters:subnet_parameters ~global_parameters:t.global_parameters
                ~serverIP: serverIP ~lease_length:lease_length ~message_type:`Ack in
                Some (server_construct_packet t ~xid:xid ~ciaddr:ciaddr ~yiaddr:ciaddr ~siaddr:serverIP ~giaddr:giaddr ~chaddr:chaddr ~flags:flags ~options:options);
              else if (dst = Ipaddr.V4.broadcast) then (*the packet was multicasted, it's a rebinding*)
                if (exists_lease client_subnet client_identifier) then (*this server is responsible for this . NB this an exact copy of the renewal code*)
                  let new_reservation = client_identifier,{ip_address=ciaddr;lease_length=lease_length;lease_timestamp=Clock.time()} in
                  remove_lease client_subnet client_identifier;
                  add_address new_reservation client_subnet.leases;
                  let options = make_options_with_lease ~client_requests: client_requests ~subnet_parameters:subnet_parameters ~global_parameters:t.global_parameters
                  ~serverIP: serverIP ~lease_length:lease_length ~message_type:`Ack in
                  Some (server_construct_packet t ~xid:xid ~ciaddr:ciaddr ~yiaddr:ciaddr ~siaddr:serverIP ~giaddr:giaddr ~chaddr:chaddr ~flags:flags ~options:options);
                else (*this server is not responsible for this binding*)
                  None
              else None (*error case, this should never be used*)
            )
      |`Decline -> (*This means that the client has discovered that the offered IP address is in use, the server responds by reserving the address until a client explicitly releases it*)
        (try
          let ip_address = (find_reservation client_subnet client_identifier).reserved_ip_address in
          let new_reservation = "Unknown", {ip_address;lease_length=Int32.max_int;lease_timestamp=Clock.time()} in (*set lease to the maximum: this means it won't expire*)
          add_address new_reservation client_subnet.leases; (*must notify network admin*)
          remove_reservation client_subnet client_identifier;
          None;
        with
          |Not_found -> None;)
      |`Release ->
        (*Console.log t.c (sprintf "Packet is a release");*)
        if (exists_lease client_subnet client_identifier) then (
          add_address ciaddr client_subnet.available_addresses;
          remove_lease client_subnet client_identifier;
          None;
          )
        else
          None;
      |`Inform ->
        let options = make_options_without_lease ~client_requests:client_requests ~serverIP:serverIP ~subnet_parameters:subnet_parameters ~global_parameters:t.global_parameters
        ~message_type:`Ack in
        Some (server_construct_packet t ~xid:xid ~ciaddr:ciaddr ~yiaddr:yiaddr ~siaddr:serverIP ~giaddr:giaddr ~chaddr:chaddr ~flags:flags ~options:options);
      | _ -> None (*this is a packet meant for a client*)
      with
      |Error _ -> None
      |Not_found -> None
  
  let read_config serverIPs filename = 
    Dhcp_serverv4_config_parser.read_DHCP_config filename serverIPs;;
  
  let rec garbage_collect t collection_interval=
    (*Console.log t.c (sprintf "GC running!");*)
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
      |subnet::tail -> subnet.reservations:=(gc_reserved !(subnet.reservations));(subnet.leases:=(gc_in_use !(subnet.leases)));gc tail
    in
    gc (t.subnets);;
    
end  
  
module Make (Console:V1_LWT.CONSOLE)
  (Clock:V1.CLOCK)
  (Stack:V1_LWT.STACKV4) = struct
  
  module H = (Helper (Console) (Clock));;
  open H;;
  
  let input t stack ~src ~dst ~src_port:_ buf =
    let dhcp_packet = dhcp_packet_of_cstruct buf in
    match parse_packet t ~src:src ~dst:dst ~packet:dhcp_packet with
    |None -> Lwt.return_unit;
    |Some (p,d) ->
      (*Console.log_s t.c (sprintf "Sending DHCP broadcast")
      >>= fun () ->*)
        Stack.UDPV4.write ~dest_ip:d ~source_port:68 ~dest_port:67 (Stack.udpv4 stack) p
    
  let server_set_up c stack =
    let serverIPs = Stack.IPV4.get_ip (Stack.ipv4 stack) in
    let subnets,global_parameters = read_config serverIPs "/etc/dhcpd.conf" in
    let server_subnet = (*assumption: all of the server's IPs are on the same subnet*)
      let test_IP = List.hd (serverIPs) in
      find_subnet test_IP subnets
    in
    {server_subnet;serverIPs;subnets;global_parameters};;
  
  let serverThread t stack =
    Stack.listen_udpv4 stack 67 (input t stack);
    Lwt.return_unit;;
  
  let start ~c ~clock ~stack = 
    let t = server_set_up c stack in
    Lwt.join([serverThread t stack;garbage_collect t 300.0]);;
end