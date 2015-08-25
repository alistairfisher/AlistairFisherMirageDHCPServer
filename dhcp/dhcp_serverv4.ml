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

module Internal (Console:V1_LWT.CONSOLE) )(*The internal part of the server (no networking) is kept separate for ease of testing*)
  (Clock:V1.CLOCK)
  (Maker:Irmin.S_MAKER) = struct
  
  exception DHCP_Server_Error of string;;
 
  module Lease_state = struct
    type t = | Reserved of (int32*string) | Active of string (*use the int32 to hold a reservations transaction id*) (*TODO: use Dhcpv4_datastructures.client_identifier instead of string*)
  
    let of_string s = 
      try
        let regexp = Str.regexp " " in
        let tokens = Str.split regexp s in
        let lease_state = List.hd tokens in
        match lease_state with
        |"Reserved" ->
          let xid = Int32.of_string (List.nth tokens 1) in
          let client_id = (List.nth tokens 2) in
          Some (Reserved (xid,client_id))
        |"Active" ->
          let client_id = (List.nth tokens 1) in
          Some (Active client_id)
      with
      | _ -> None;;
  
    let to_string = function
      |Reserved (xid,client_identifier)-> Printf.sprintf "Reserved %s %s" (Int32.to_string xid) client_identifier
      |Active client_identifier-> Printf.sprintf "Active %s" client_identifier;;
    
    let compare x y =
      match (x,y) with
      |(Reserved _),(Active _) -> -1
      |(Active _),(Reserved _) -> 1
      | _ -> 0;;
  end
 
  module Entry = Inds_entry.Make(Lease_state)
  module Table = Inds_table.Make(Ipaddr.V4)(Entry)(Irmin.Path.String_list)
  module I = Irmin.Basic(Maker)(T)
 
  module Data_structures

    type reserved_address = { (*An address that has been offered to a client, but not yet accepted*)
      reserved_ip_address: Ipaddr.V4.t;
      xid: Cstruct.uint32;
      reservation_timestamp: float;
    }
  
    type lease = {
      lease_length:int32;
      lease_timestamp:float;
      ip_address: Ipaddr.V4.t;
    }

  
    (*TODO: use client ID to differentiate explicit ID from hardware address, allowing different hardware types.*)    
    type client_identifier = string;; (*According to RFC 2131, this should be the client's hardware address unless an explicit identifier is provided. The RFC states that the ID must be unique
    within the subnet, but the onus is on the client to ensure this if it chooses to use an explicit identifier: the server shouldn't need to check it for uniqueness. The
    full identifier is the combination of subnet and identifier, but the subnet is implicit in this implementation*)

    type subnet = {
      subnet: Ipaddr.V4.t;
      netmask: Ipaddr.V4.t;
      parameters: Dhcpv4_option.t list;
      scope_bottom: Ipaddr.V4.t;
      scope_top: Ipaddr.V4.t;
      max_lease_length: int32;
      default_lease_length: int32;
      serverIP: Ipaddr.V4.t; (*The IP address of the interface that should be used to communicate with hosts on this subnet*)
      static_hosts: (string*Ipaddr.V4.t) list;
      table: I.t;
    }
    
  end
 
  let rec find_subnet ip_address subnets = (*Match an IP address to a subnet*)
    let routing_prefix netmask address= (*Find the routing prefix of address if it lived in the subnet with this netmask*)
      let x = Ipaddr.V4.to_int32 address in
      let y = Ipaddr.V4.to_int32 netmask in
      Ipaddr.V4.of_int32(Int32.logand x y)
    in
    let compare_address_to_subnet subnet = (*Compare the supplied ip address to one subnet: the ip address is in the subnet if they have the same routing prefix*)
      let prefix = routing_prefix (subnet.netmask) in
      (prefix subnet.subnet)=(prefix ip_address)
    in
    match subnets with
    |[] -> raise (DHCP_Server_Error (Printf.sprintf "Subnet not found for address %s" (Ipaddr.V4.to_string(ip_address))))
    |h::t ->
      if (compare_address_to_subnet h) then h
      else find_subnet ip_address t;; 
  
  (*Irmin helpers*)
  
  let change_address_state address state subnet lease_time =
    let lease_time = Int32.to_int lease_time in
    let entry = Dhcpv4_irmin.Entry.make_confirmed ((int_of_float(Clock.time())) + lease_time) state in
    subnet.table := Dhcpv4_irmin.Table.add address entry !(subnet.table);;
  
  let add_address address state subnet lease_time =
    let lease_time = Int32.to_int lease_time in
    let entry = Dhcpv4_irmin.Entry.make_confirmed ((int_of_float(Clock.time())) + lease_time) state in
    let new_table = Dhcpv4_irmin.Table.add address (I.get_head_exn subnet.table) in
    
  
  let find_address address subnet =
    let Dhcpv4_irmin.Entry.Confirmed(time,lease_state) = Dhcpv4_irmin.Table.find address !(subnet.table) in
    lease_state;; 
  
  let remove_address address subnet =
    subnet.table := Dhcpv4_irmin.Table.remove address !(subnet.table);;
  
  let check_reservation address subnet xid client_identifier = (*Check whether a request uses the correct xid and client id for the reservation*)
    try
      let Dhcpv4_irmin.Entry.Confirmed(time,address_state) = Dhcpv4_irmin.Table.find address !(subnet.table) in
      address_state = (Dhcpv4_irmin.Lease_state.Reserved (xid,client_identifier))
    with
    | Not_found -> false;;
  
  let first_address subnet =  (*first available address*)
    let scope_bottom = Ipaddr.V4.to_int32 subnet.scope_bottom in
    let scope_top = Ipaddr.V4.to_int32 subnet.scope_top in
    let rec check_address ip_address =
      if ip_address>scope_top then raise (DHCP_Server_Error (Printf.sprintf "No available IP addresses in subnet %s" (Ipaddr.V4.to_string subnet.subnet)))
      else
        let ip_of_int32 = Ipaddr.V4.of_int32 ip_address in
        if Dhcpv4_irmin.Table.mem ip_of_int32 !(subnet.table) then
          check_address (Int32.add ip_address Int32.one)
        else ip_of_int32
    in
    check_address scope_bottom;;

  let is_available address subnet = 
    not (Dhcpv4_irmin.Table.mem address !(subnet.table)) && (subnet.scope_bottom <= address) && (subnet.scope_top>= address);;
  
  let check_static_hosts client_identifier subnet =
    try
      Some (List.assoc client_identifier (subnet.static_hosts))
    with
    |Not_found -> None;;
  
  type t = {
    c: Console.t;
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
    (*Lwt_list.iter_s (Console.log_s t.c)
      [ "DHCP response:";
        sprintf "input ciaddr %s yiaddr %s" (Ipaddr.V4.to_string ciaddr) (Ipaddr.V4.to_string yiaddr);
        sprintf "siaddr %s giaddr %s" (Ipaddr.V4.to_string siaddr) (Ipaddr.V4.to_string giaddr);
        sprintf "chaddr %s sname %s file %s" (chaddr) (copy_dhcp_sname buf) (copy_dhcp_file buf)]
    >>= fun () ->*)
    try
      let open Dhcpv4_option.Packet in
      let client_identifier = match find packet (function `Client_id id -> Some id |_ -> None) with (*If a client ID is explcitly provided, use it, else default to using client hardware address for id*)
        |None -> chaddr
        |Some id-> 
          id
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
        let reserved_ip_address = 
          match (check_static_hosts client_identifier client_subnet) with
          |Some address ->
            Console.log t.c (Printf.sprintf "Allocating static address %s to host %s" (Ipaddr.V4.to_string address) client_identifier);
            address
          |None ->
             match find packet (function `Requested_ip requested_address -> Some requested_address | _ -> None) with (*check whether the client has requested a specific address, and if possible reserve it for them*)
             |None->
               let reservation = first_address client_subnet in
               Console.log t.c (Printf.sprintf "No requested address from client %s, allocating address %s" client_identifier (Ipaddr.V4.to_string reservation));
               reservation
             |Some requested_address ->
              if (is_available requested_address client_subnet) then
                (*Console.log t.c (Printf.sprintf "Host %s requested address %s, this was available and has been allocated" client_identifier (Ipaddr.V4.to_string requested_address));*)
                requested_address
              else
                let reservation = first_address client_subnet in
                Console.log t.c (Printf.sprintf "Host %s requested address %s, this was unavailable and address %s has been allocated instead" client_identifier
                  (Ipaddr.V4.to_string requested_address) (Ipaddr.V4.to_string reservation));
                reservation
        in
        add_address reserved_ip_address (Dhcpv4_irmin.Lease_state.Reserved (xid,client_identifier)) client_subnet lease_length;
        let options = make_options_with_lease ~client_requests: client_requests ~subnet_parameters:subnet_parameters ~global_parameters:t.global_parameters
        ~serverIP: serverIP ~lease_length:lease_length ~message_type:`Offer in
        Some (server_construct_packet t ~xid:xid ~ciaddr:ciaddr ~yiaddr:reserved_ip_address ~siaddr:serverIP ~giaddr:giaddr ~chaddr:chaddr ~flags:flags ~options:options);
      |`Request ->
        (match (find packet(function `Server_identifier id ->Some id |_ -> None)) with
          |Some server_identifier -> (*This is a response to an offer*)
            let requested_ip_address = match find packet (function `Requested_ip ip -> Some ip |_ -> None) with
              |None -> raise (DHCP_Server_Error (Printf.sprintf "DHCP Request -  Select with no requested IP from client %s" client_identifier))
              |Some ip_address -> ip_address
            in
            if ((List.mem server_identifier t.serverIPs) && (check_reservation requested_ip_address client_subnet xid client_identifier)) then (
              change_address_state requested_ip_address (Dhcpv4_irmin.Lease_state.Active client_identifier) client_subnet lease_length;
              let options = make_options_with_lease ~client_requests: client_requests ~subnet_parameters:subnet_parameters ~global_parameters:t.global_parameters
              ~serverIP: serverIP ~lease_length:lease_length ~message_type:`Ack in
              Some (server_construct_packet t ~xid:xid ~ciaddr:ciaddr ~yiaddr:requested_ip_address ~siaddr:serverIP ~giaddr:giaddr ~chaddr:chaddr ~flags:flags ~options:options);
            )
            else None; (*either the request is for a different server or the xid doesn't match the server's most recent transaction with that client*)
          |None -> (*this is a renewal, rebinding or init_reboot.*)
            if (ciaddr = Ipaddr.V4.unspecified) then (*client in init-reboot*)
              let requested_IP = match find packet (function `Requested_ip ip -> Some ip |_ -> None) with
                |None -> raise (DHCP_Server_Error (Printf.sprintf "init-reboot with no requested IP from client %s" client_identifier))
                |Some ip_address -> ip_address
              in
              if (is_available requested_IP client_subnet) then (*address is available, lease to client*)
                let f = change_address_state requested_IP (Dhcpv4_irmin.Lease_state.Active client_identifier) client_subnet lease_length in
                f;
                let options = make_options_with_lease ~client_requests: client_requests ~subnet_parameters:subnet_parameters ~global_parameters:t.global_parameters
                ~serverIP: serverIP ~lease_length:lease_length ~message_type:`Ack in
                Some (server_construct_packet t ~xid:xid ~ciaddr:(Ipaddr.V4.unspecified) ~yiaddr:requested_IP ~siaddr:serverIP ~giaddr:giaddr ~chaddr:chaddr ~flags:flags ~options:options);
              else (*address is not available, either because it's taken or because it's not on this subnet send Nak*)
                let options = make_options_without_lease ~serverIP:serverIP ~message_type:`Nak ~client_requests: client_requests
                ~subnet_parameters:subnet_parameters ~global_parameters:t.global_parameters in
                Some (server_construct_packet t ~xid:xid ~nak:true ~ciaddr:(Ipaddr.V4.unspecified) ~yiaddr:(Ipaddr.V4.unspecified) ~siaddr:(Ipaddr.V4.unspecified) ~giaddr:giaddr ~chaddr:chaddr ~flags:flags ~options:options);
            else (*client in renew or rebind.*)
              if (dst = serverIP) then (*the packet was unicasted here, it's a renewal. Currently accept all renewals*)
                (*Note: RFC 2131 states that the server should trust the client here, despite potential security issues*)
                let table = change_address_state ciaddr (Dhcpv4_irmin.Lease_state.Active client_identifier) client_subnet lease_length in
                table;
                let options = make_options_with_lease ~client_requests: client_requests ~subnet_parameters:subnet_parameters ~global_parameters:t.global_parameters
                ~serverIP: serverIP ~lease_length:lease_length ~message_type:`Ack in
                Some (server_construct_packet t ~xid:xid ~ciaddr:ciaddr ~yiaddr:ciaddr ~siaddr:serverIP ~giaddr:giaddr ~chaddr:chaddr ~flags:flags ~options:options);
              else if (dst = Ipaddr.V4.broadcast) then (*the packet was multicasted, it's a rebinding*)
                let address_info = find_address ciaddr client_subnet in
                if (address_info = Dhcpv4_irmin.Lease_state.Active client_identifier) then (*this server is responsible for this.*)
                  let table = change_address_state ciaddr (Dhcpv4_irmin.Lease_state.Active client_identifier) client_subnet lease_length in
                  table;
                  let options = make_options_with_lease ~client_requests: client_requests ~subnet_parameters:subnet_parameters ~global_parameters:t.global_parameters
                  ~serverIP: serverIP ~lease_length:lease_length ~message_type:`Ack in
                  Some (server_construct_packet t ~xid:xid ~ciaddr:ciaddr ~yiaddr:ciaddr ~siaddr:serverIP ~giaddr:giaddr ~chaddr:chaddr ~flags:flags ~options:options);
                else (*this server is not responsible for this binding*)
                  None
              else None
            )
      |`Decline -> (*This means that the client has discovered that the offered IP address is in use, the server responds by reserving the address until a client explicitly releases it*)
        (match find packet (function `Requested_ip ip -> Some ip |_ -> None) with
          |None -> None
          |Some ip_address ->
            change_address_state ip_address (Dhcpv4_irmin.Lease_state.Active "client_unknown") client_subnet lease_length;
            None
        )
      |`Release ->
        remove_address ciaddr client_subnet;
        None          
      |`Inform ->
        let options = make_options_without_lease ~client_requests:client_requests ~serverIP:serverIP ~subnet_parameters:subnet_parameters ~global_parameters:t.global_parameters
        ~message_type:`Ack in
        Some (server_construct_packet t ~xid:xid ~ciaddr:ciaddr ~yiaddr:yiaddr ~siaddr:serverIP ~giaddr:giaddr ~chaddr:chaddr ~flags:flags ~options:options);
      | _ -> None (*this is a packet meant for a client*)
      with
      |DHCP_Server_Error message ->
        let timestamp = Clock.time() in
        let error_message = Printf.sprintf "[%f] Dhcp server error: %s" timestamp message in
        Console.log t.c error_message;
        None
      |Not_found -> None
  
  let read_config serverIPs filename = 
    Dhcp_serverv4_config_parser.read_DHCP_config filename serverIPs;;
 
  let rec garbage_collect t collection_interval =
    Console.log t.c (sprintf "GC running!");
    let gc_subnet subnet = subnet.table := (Dhcpv4_irmin.Table.expire !(subnet.table) (int_of_float (Clock.time()))) in
    let rec gc = function
      |[] -> Time.sleep collection_interval >>= fun () -> garbage_collect t collection_interval
      |h::t -> (gc_subnet h);(gc t)
   in   
   gc (t.subnets);;
    
end  
  
module Make (Console:V1_LWT.CONSOLE)
  (Clock:V1.CLOCK)
  (Udp:V1_LWT.UDPV4)
  (Ip:V1_LWT.IPV4)
  (Maker:Irmin.S_MAKER) = struct
  
  module H = (Internal (Console) (Clock) (Maker));;
  open H;;
  
  let input t udp ~src ~dst ~src_port:_ buf =
    let dhcp_packet = dhcp_packet_of_cstruct buf in
    Console.log t.c (Printf.sprintf "Packet received from host %s" (Ipaddr.V4.to_string src));
    match parse_packet t ~src:src ~dst:dst ~packet:dhcp_packet with
    |None -> Lwt.return_unit;
    |Some (p,d) ->
      Console.log_s t.c "Sending DHCP broadcast"
      >>= fun () ->
        Udp.write ~dest_ip:d ~source_port:68 ~dest_port:67 udp p
    
  let server_set_up c ip =
    let serverIPs = Ip.get_ip ip in
    let sample_server_ip = List.hd serverIPs in
    let subnets,global_parameters = read_config serverIPs "/etc/dhcpd.conf" in
    let server_subnet = find_subnet sample_server_ip subnets in
    {c;server_subnet;serverIPs;subnets;global_parameters};;
  
  let serverThread t udp =
    let listener ~dst_port =
      match dst_port with
      |67 -> Some (input t udp)
      |_ -> None
    in
    let make_unit x = Lwt.return_unit in
    make_unit (Udp.input ~listeners:listener udp);;
  
  let start ~c ~clock ~udp ~ip = 
    let t = server_set_up c ip in
    Lwt.join [serverThread t udp;garbage_collect t 60.0];;
end