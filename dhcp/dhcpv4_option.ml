(*
 * Copyright (c) 2006-2010 Anil Madhavapeddy <anil@recoil.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
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
 *
 *)

open Printf

(* This is a hand-crafted DHCP option parser. Did not use MPL
   here as it doesn't have enough variable length array support
   yet. At some point, this should be rewritten to use more of the
   autogen Mpl_stdlib *)

type msg = [
  |`Pad
  |`Subnet_mask
  |`Time_offset
  |`Router
  |`Time_server
  |`Name_server
  |`Dns_server
  |`Log_server
  |`Cookie_server
  |`Lpr_server
  |`Impress_server
  |`Rlp_server
  |`Hostname
  |`Boot_file_size
  |`Merit_dump_file
  |`Domain_name
  |`Swap_server
  |`Root_path
  |`Extensions_path
  |`Ip_forwarding
  |`Non_local_source_routing
  |`Policy_filter
  |`Max_datagram_reassembly
  |`Default_ip_ttl
  |`Mtu_timeout
  |`Mtu_plateau
  |`Mtu_interface
  |`All_subnets_local
  |`Broadcast_address
  |`Mask_discovery
  |`Mask_supplier
  |`Router_discovery
  |`Router_request
  |`Static_route
  |`Trailers
  |`Arp_timeout
  |`Ethernet
  |`Default_tcp_ttl
  |`Keepalive_time
  |`Keepalive_data
  |`Nis_domain
  |`Nis_servers
  |`Ntp_servers
  |`Vendor_specific
  |`Netbios_name_server
  |`Netbios_dist_srv
  |`Netbios_node_type
  |`Netbios_scope
  |`X_window_font_server
  |`X_window_manager
  |`Requested_ip_address
  |`Requested_lease
  |`Option_overload
  |`Message_type
  |`Server_identifier
  |`Parameter_request
  |`Message
  |`Max_size
  |`Renewal_time
  |`Rebinding_time
  |`Vendor_class_id
  |`Client_identifier
  |`Netware_domain
  |`Netware_option
  |`Nis_domain_name
  |`Nis_server_addr
  |`Tftp_server_name
  |`Bootfile_name
  |`Mobile_ip_home_agent_addrs
  |`Smtp_server
  |`Pop3_server
  |`Nntp_server
  |`Www_server
  |`Finger_server
  |`Irc_server
  |`Streettalk_server
  |`Stda_server
  |`Domain_search (* RFC 3397 *)
  |`End
  |`Unknown of char
]

type op = [  (* DHCP operations *)
  |`Discover
  |`Offer
  |`Request
  |`Decline
  |`Ack
  |`Nak
  |`Release
  |`Inform
  |`Unknown of char
]

type t = [
  |`Pad 
  |`Subnet_mask of Ipaddr.V4.t (*TODO: use prefix?*)
  |`Time_offset of string
  |`Router of Ipaddr.V4.t list
  |`Time_server of Ipaddr.V4.t list
  |`Name_server of Ipaddr.V4.t list
  |`Dns_server of Ipaddr.V4.t list
  |`Log_server of Ipaddr.V4.t list
  |`Cookie_server of Ipaddr.V4.t list
  |`Lpr_server of Ipaddr.V4.t list
  |`Impress_server of Ipaddr.V4.t list
  |`Rlp_server of Ipaddr.V4.t list
  |`Hostname of string
  |`Boot_file_size of int (*16 bit unsigned*)
  |`Merit_dump_file of string
  |`Domain_name of string
  |`Swap_server of Ipaddr.V4.t
  |`Root_path of string
  |`Extensions_path of string
  |`Ip_forwarding of bool
  |`Non_local_source_routing of bool
  |`Policy_filter of (Ipaddr.V4.t * Ipaddr.V4.t) list (*use prefix?*)
  |`Max_datagram_reassembly of int(*16 bit int*)
  |`Default_ip_ttl of int (*8 bit int*)
  |`Mtu_timeout of int32 (*unsigned*)
  |`Mtu_plateau of int list(*list of 16 bit integers, length >=1*)
  |`Mtu_interface of int(*16 bit int*)
  |`All_subnets_local of bool
  |`Broadcast_address of Ipaddr.V4.t
  |`Mask_discovery of bool
  |`Mask_supplier of bool
  |`Router_discovery of bool
  |`Router_request of Ipaddr.V4.t
  |`Static_route of (Ipaddr.V4.t * Ipaddr.V4.t) list list
  |`Trailers of bool
  |`Arp_timeout of int32 (*unsigned*)
  |`Ethernet of bool
  |`Default_tcp_ttl of int(*8 bit integer*) 
  |`Keepalive_time of int32 (*unsigned*)
  |`Keepalive_data of bool
  |`Nis_domain of string
  |`Nis_servers of Ipaddr.V4.t list
  |`Ntp_servers of Ipaddr.V4.t list
  (*|`Vendor_specific of (*TODO*)*)
  |`Netbios_name_server of Ipaddr.V4.t list
  |`Netbios_dist_srv of Ipaddr.V4.t list
  |`Netbios_node_type of int(*8 bit int*)
  (*|`Netbios_scope of (*TODO*)*)
  |`X_window_font_server of Ipaddr.V4.t
  |`X_window_manager of Ipaddr.V4.t
  |`Requested_ip_address of Ipaddr.V4.t
  |`Requested_lease of int32 (*unsigned*)
  |`Option_overload of int(*8 bit int*)
  |`Message_type of op
  |`Server_identifier of Ipaddr.V4.t
  |`Parameter_request of msg list
  |`Message of string
  |`Max_size of int (*16 bit int*)
  |`Renewal_time of int32 (*unsigned*)
  |`Rebinding_time of int32 (*unsigned*)
  (*|`Vendor_class_id of*)
  |`Client_identifier of string (*TODO: extend to hardware type*hardware address*) 
  |`Netware_domain of string
  (*|`Netware_option of (*TODO*)*)
  |`Nis_domain_name of string
  |`Nis_server_addr of Ipaddr.V4.t list
  (*|`Tftp_server_name of*) (*TODO*)
  (*|`Bootfile_name of *)(*TODO*)
  |`Mobile_ip_home_agent_addrs of Ipaddr.V4.t list
  |`Smtp_server of Ipaddr.V4.t list
  |`Pop3_server of Ipaddr.V4.t list
  |`Nntp_server of Ipaddr.V4.t list
  |`Www_server of Ipaddr.V4.t list
  |`Finger_server of Ipaddr.V4.t list
  |`Irc_server of Ipaddr.V4.t list
  |`Streettalk_server of Ipaddr.V4.t list
  |`Stda_server of Ipaddr.V4.t list
  |`Domain_search of string
  |`Unknown of (char*string) (*code and buffer*)
  |`End
]

let msg_to_string = function
  |`Pad -> "Pad"
  |`Subnet_mask -> "Subnet_mask"
  |`Time_offset -> "Time_offset"
  |`Router -> "Router"
  |`Time_server -> "Time_server"
  |`Name_server -> "Name_server"
  |`Dns_server -> "Dns_server"
  |`Log_server -> "Log_server"
  |`Cookie_server -> "Cookie_server"
  |`Lpr_server -> "Lpr_server"
  |`Impress_server -> "Impress_server"
  |`Rlp_server -> "Rlp_server"
  |`Hostname -> "Hostname"
  |`Boot_file_size -> "Boot_file_size"
  |`Merit_dump_file -> "Merit_dump_file"
  |`Domain_name -> "Domain_name"
  |`Swap_server -> "Swap_server"
  |`Root_path -> "Root_path"
  |`Extensions_path -> "Extensions_path"
  |`Ip_forwarding -> "Ip_forwarding"
  |`Non_local_source_routing -> "Non_local_source_routing"
  |`Policy_filter -> "Policy_filter"
  |`Max_datagram_reassembly -> "Max_datagram_reassembly"
  |`Default_ip_ttl -> "Default_ip_ttl"
  |`Mtu_timeout -> "Mtu_timeout"
  |`Mtu_plateau -> "Mtu_plateau"
  |`Mtu_interface -> "Mtu_interface"
  |`All_subnets_local -> "All_subnets_local"
  |`Broadcast_address -> "Broadcast_address"
  |`Mask_discovery -> "Mask_discovery"
  |`Mask_supplier -> "Mask_supplier"
  |`Router_discovery -> "Router_discovery"
  |`Router_request -> "Router_request"
  |`Static_route -> "Static_route"
  |`Trailers -> "Trailers"
  |`Arp_timeout -> "Arp_timeout"
  |`Ethernet -> "Ethernet"
  |`Default_tcp_ttl -> "Default_tcp_ttl"
  |`Keepalive_time -> "Keepalive_time"
  |`Keepalive_data -> "Keepalive_data"
  |`Nis_domain -> "Nis_domain"
  |`Nis_servers -> "Nis_servers"
  |`Ntp_servers -> "Ntp_servers"
  |`Vendor_specific -> "Vendor_specific"
  |`Netbios_name_server -> "Netbios_name_server"
  |`Netbios_dist_srv -> "Netbios_dist_srv"
  |`Netbios_node_type -> "Netbios_node_type"
  |`Netbios_scope -> "Netbios_scope"
  |`X_window_font_server -> "X_window_font_server"
  |`X_window_manager -> "X_window_manager"
  |`Requested_ip_address -> "Requested_ip_address"
  |`Requested_lease -> "Requested_lease"
  |`Option_overload -> "Option_overload"
  |`Message_type -> "Message_type"
  |`Server_identifier -> "Server_identifier"
  |`Parameter_request -> "Parameter_request"
  |`Message -> "Message"
  |`Max_size -> "Max_size"
  |`Renewal_time -> "Renewal_time"
  |`Rebinding_time -> "Rebinding_time"
  |`Vendor_class_id -> "Vendor_class_id"
  |`Client_identifier -> "Client_identifier"
  |`Netware_domain -> "Netware_domain"
  |`Netware_option -> "Netware_option"
  |`Nis_domain_name -> "Nis_domain_name"
  |`Nis_server_addr -> "Nis_server_addr"
  |`Tftp_server_name -> "Tftp_server_name"
  |`Bootfile_name -> "Bootfile_name"
  |`Mobile_ip_home_agent_addrs -> "Mobile_ip_home_agent_addrs"
  |`Smtp_server -> "Smtp_server"
  |`Pop3_server -> "Pop3_server"
  |`Nntp_server -> "Nntp_server"
  |`Www_server -> "Www_server"
  |`Finger_server -> "Finger_server"
  |`Irc_server -> "Irc_server"
  |`Streettalk_server -> "Streettalk_server"
  |`Stda_server -> "Stda_server"
  |`Domain_search -> "Domain_search"
  |`Unknown c -> sprintf "Unknown(%d)" (Char.code c)
  |`End -> "End";;

let op_to_string (x:op) =
  match x with
  |`Discover -> "Discover"
  |`Offer -> "Offer"
  |`Request -> "Request"
  |`Decline -> "Decline"
  |`Ack -> "Ack"
  |`Nak -> "Nack"
  |`Release -> "Release"
  |`Inform -> "Inform"
  |`Unknown x -> "Unknown " ^ (string_of_int (Char.code x))

let t_to_string (t:t) =
  let ip_one s ip = sprintf "%s(%s)" s (Ipaddr.V4.to_string ip) in
  let ip_list s ips = sprintf "%s(%s)" s (String.concat "," (List.map Ipaddr.V4.to_string ips)) in
  let ip_pair (s1,s2) = sprintf "%s,%s" (Ipaddr.V4.to_string s1) (Ipaddr.V4.to_string s2) in
  let ip_pair_list s ips =
    sprintf "%s(%s)" s (String.concat "," (List.map ip_pair ips))
  in
  let ip_pair_list_list s ips =
    let ip_pair_list ips = (String.concat "," (List.map ip_pair ips)) in
    sprintf "%s(%s)" s (String.concat "," (List.map ip_pair_list ips))
  in
  let str s v = sprintf "%s(%s)" s (String.escaped v) in
  let strs s v = sprintf "%s(%s)" s (String.concat "," v) in
  let i32 s v = sprintf "%s(%lu)" s v in
  let int_list s v = sprintf "%s(%s)" s (String.concat "," (List.map string_of_int v)) in
  let boolean s v = sprintf "%s(%b)" s v in
  match t with
  |`Pad -> "Pad"
  |`Subnet_mask ip -> ip_one "Subnet mask" ip
  |`Time_offset _ -> "Time offset"
  |`Router ips  -> ip_list "Routers" ips
  |`Time_server ips -> ip_list "Time servers" ips
  |`Name_server ips -> ip_list "Name servers" ips
  |`Dns_server ips -> ip_list "Dns servers" ips
  |`Log_server ips -> ip_list "Log servers" ips
  |`Cookie_server ips -> ip_list "Cookie servers" ips
  |`Lpr_server ips -> ip_list "Lpr servers" ips
  |`Impress_server ips -> ip_list "Impress servers" ips
  |`Rlp_server ips -> ip_list "Rlp servers" ips
  |`Hostname s -> str "Host name" s
  |`Boot_file_size sz -> str "Boot file size" (string_of_int sz)
  |`Merit_dump_file s -> str "Merit dump file" s
  |`Domain_name s -> str "Domain name" s
  |`Swap_server ip -> ip_one "Swap server" ip
  |`Root_path s -> str "Root path" s
  |`Extensions_path s -> str "Extensions path" s
  |`Ip_forwarding b -> boolean "Ip forwarding" b
  |`Non_local_source_routing b -> boolean "Non local source routing" b
  |`Policy_filter ips -> ip_pair_list "Policy filter" ips
  |`Max_datagram_reassembly max -> str "Max datagram reassembly" (string_of_int max)
  |`Default_ip_ttl ttl -> str "Max ip ttl" (string_of_int ttl)
  |`Mtu_timeout tm -> i32 "Path MTU aging timeout" tm
  |`Mtu_plateau ints -> int_list "Path MTU plateau table" ints
  |`Mtu_interface i -> str "Interface MTU" (string_of_int i)
  |`All_subnets_local b -> boolean "All subnets local" b
  |`Broadcast_address x -> ip_one "Broadcast" x
  |`Mask_discovery b -> boolean "Mask discovery" b
  |`Mask_supplier b -> boolean "Mask supplier" b
  |`Router_discovery b -> boolean "Router discovery" b
  |`Router_request ip -> ip_one "Router request" ip
  |`Static_route ips -> ip_pair_list_list "Static routes" ips
  |`Trailers b -> boolean "Trailer encapsulation" b
  |`Arp_timeout tm -> i32 "Arp timeout" tm
  |`Ethernet e -> boolean "Ethernet encapsulation" e
  |`Default_tcp_ttl t -> str "Default tcp ttl" (string_of_int t)
  |`Keepalive_time k -> i32 "Keepalive time" k
  |`Keepalive_data b -> boolean "Keepalive data" b
  |`Nis_domain s -> str "Nis domain" s
  |`Nis_servers ips -> ip_list "Nis servers" ips
  |`Ntp_servers ips -> ip_list "Ntp servers" ips
  |`Netbios_name_server d -> ip_list "NetBIOS name server" d
  |`Netbios_dist_srv d -> ip_list "Netbios distribution server" d
  |`Netbios_node_type n -> str "Netbios node type" (string_of_int n)
  |`X_window_font_server x -> ip_one "X window font server" x
  |`X_window_manager x -> ip_one "X window display manager" x
  |`Requested_ip_address ip -> ip_one "Requested ip" ip
  |`Requested_lease tm -> i32 "Lease time" tm
  |`Option_overload o -> str "Option overload" (string_of_int o)
  |`Message_type op -> str "Message type" (op_to_string op)
  |`Server_identifier ip -> ip_one "Server identifer" ip
  |`Parameter_request ps -> strs "Parameter request" (List.map msg_to_string ps)
  |`Message s -> str "Message" s
  |`Max_size sz -> str "Max size" (string_of_int sz)
  |`Renewal_time r -> i32 "Renewal time" r
  |`Rebinding_time r -> i32 "Rebinding time" r
  |`Client_identifier id -> str "Client id" id
  |`Netware_domain s -> str "Netware domain" s
  |`Nis_domain_name s -> str "Nis+ domain name" s
  |`Nis_server_addr ips -> ip_list "Nis+ server address" ips
  |`Mobile_ip_home_agent_addrs ips -> ip_list "Mobile ip home agent addresses" ips
  |`Smtp_server ips -> ip_list "Smtp server" ips
  |`Pop3_server ips -> ip_list "Pop3 server" ips
  |`Nntp_server ips -> ip_list "Nntp server" ips
  |`Www_server ips -> ip_list "Www server" ips
  |`Finger_server ips -> ip_list "Finger server" ips
  |`Irc_server ips -> ip_list "Irc server" ips
  |`Streettalk_server ips -> ip_list "Streettalk server" ips
  |`Stda_server ips -> ip_list "Streettalk directory assistance server" ips
  |`Domain_search d -> str "Domain search" d
  |`Unknown (c,x) -> sprintf "Unknown(%d[%d])" (Char.code c) (Bytes.length x)
  |`End -> "End"

  let t_equal_to_msg t msg =
    match t,msg with
    |`Pad,`Pad -> true
    |`Subnet_mask _,`Subnet_mask -> true
    |`Time_offset _,`Time_offset -> true
    |`Router _,`Router -> true
    |`Time_server _,`Time_server -> true
    |`Name_server _,`Name_server -> true
    |`Dns_server _,`Dns_server -> true
    |`Log_server _,`Log_server -> true
    |`Cookie_server _,`Cookie_server -> true
    |`Lpr_server _,`Lpr_server -> true
    |`Impress_server _,`Impress_server -> true
    |`Rlp_server _,`Rlp_server -> true
    |`Hostname _,`Hostname -> true
    |`Boot_file_size _,`Boot_file_size -> true
    |`Merit_dump_file _,`Merit_dump_file -> true
    |`Domain_name _,`Domain_name -> true
    |`Swap_server _,`Swap_server -> true
    |`Root_path _,`Root_path -> true
    |`Extensions_path _,`Extensions_path -> true
    |`Ip_forwarding _,`Ip_forwarding -> true
    |`Non_local_source_routing _,`Non_local_source_routing -> true
    |`Policy_filter _,`Policy_filter -> true
    |`Max_datagram_reassembly _,`Max_datagram_reassembly -> true
    |`Default_ip_ttl _,`Default_ip_ttl -> true
    |`Mtu_timeout _,`Mtu_timeout -> true
    |`Mtu_plateau _,`Mtu_plateau -> true
    |`Mtu_interface _,`Mtu_interface -> true
    |`All_subnets_local _,`All_subnets_local -> true
    |`Broadcast_address _,`Broadcast_address -> true
    |`Mask_discovery _,`Mask_discovery -> true
    |`Mask_supplier _,`Mask_supplier -> true
    |`Router_discovery _,`Router_discovery -> true
    |`Router_request _,`Router_request -> true
    |`Static_route _,`Static_route -> true
    |`Trailers _,`Trailers -> true
    |`Arp_timeout _,`Arp_timeout -> true
    |`Ethernet _,`Ethernet -> true
    |`Default_tcp_ttl _,`Default_tcp_ttl -> true
    |`Keepalive_time _,`Keepalive_time -> true
    |`Keepalive_data _,`Keepalive_data -> true
    |`Nis_domain _,`Nis_domain -> true
    |`Nis_servers _,`Nis_servers -> true
    |`Ntp_servers _,`Ntp_servers -> true
    (*|`Vendor_specific _,`Vendor_specific -> true*)
    |`Netbios_name_server _,`Netbios_name_server -> true
    |`Netbios_dist_srv _,`Netbios_dist_srv -> true
    |`Netbios_node_type _,`Netbios_node_type -> true
    (*|`Netbios_scope _,`Netbios_scope -> true*)
    |`X_window_font_server _,`X_window_font_server -> true
    |`X_window_manager _,`X_window_manager -> true
    |`Requested_ip_address _,`Requested_ip_address -> true
    |`Requested_lease _,`Requested_lease -> true
    |`Option_overload _,`Option_overload -> true
    |`Message_type _,`Message_type -> true
    |`Server_identifier _,`Server_identifier -> true
    |`Parameter_request _,`Parameter_request -> true
    |`Message _,`Message -> true
    |`Max_size _,`Max_size -> true
    |`Renewal_time _,`Renewal_time -> true
    |`Rebinding_time _,`Rebinding_time -> true
    (*|`Vendor_class_id _,`Vendor_class_id -> true*)
    |`Client_identifier _,`Client_identifier -> true
    |`Netware_domain _,`Netware_domain -> true
    (*|`Netware_option _,`Netware_option -> true*)
    |`Nis_domain_name _,`Nis_domain_name -> true
    |`Nis_server_addr _,`Nis_server_addr -> true
    (*|`Tftp_server_name _,`Tftp_server_name -> true
    |`Bootfile_name _,`Bootfile_name -> true*)
    |`Mobile_ip_home_agent_addrs _,`Mobile_ip_home_agent_addrs -> true
    |`Smtp_server _,`Smtp_server -> true
    |`Pop3_server _,`Pop3_server -> true
    |`Nntp_server _,`Nntp_server -> true
    |`Www_server _,`Www_server -> true
    |`Finger_server _,`Finger_server -> true
    |`Irc_server _,`Irc_server -> true
    |`Streettalk_server _,`Streettalk_server -> true
    |`Stda_server _,`Stda_server -> true
    |`End,`End -> true
    |_ -> false

let ipv4_addr_of_bytes x =
  let open Int32 in
  let b n = of_int (Char.code (x.[n])) in
  let r = add (add (add (shift_left (b 0) 24) (shift_left (b 1) 16)) (shift_left (b 2) 8)) (b 3) in
  Ipaddr.V4.of_int32 r

module Marshal = struct
  
  let t_to_code (x:msg) =
    match x with
    |`Pad -> 0
    |`Subnet_mask -> 1
    |`Time_offset -> 2
    |`Router -> 3
    |`Time_server -> 4
    |`Name_server -> 5
    |`Dns_server -> 6
    |`Log_server -> 7
    |`Cookie_server -> 8
    |`Lpr_server -> 9
    |`Impress_server -> 10
    |`Rlp_server -> 11
    |`Hostname -> 12
    |`Boot_file_size -> 13
    |`Merit_dump_file -> 14
    |`Domain_name -> 15
    |`Swap_server -> 16
    |`Root_path -> 17
    |`Extensions_path -> 18
    |`Ip_forwarding -> 19
    |`Non_local_source_routing -> 20
    |`Policy_filter -> 21
    |`Max_datagram_reassembly -> 22
    |`Default_ip_ttl -> 23
    |`Mtu_timeout -> 24
    |`Mtu_plateau -> 25
    |`Mtu_interface -> 26
    |`All_subnets_local -> 27
    |`Broadcast_address -> 28
    |`Mask_discovery -> 29
    |`Mask_supplier -> 30
    |`Router_discovery -> 31
    |`Router_request -> 32
    |`Static_route -> 33
    |`Trailers -> 34
    |`Arp_timeout -> 35
    |`Ethernet -> 36
    |`Default_tcp_ttl -> 37
    |`Keepalive_time -> 38
    |`Keepalive_data -> 39
    |`Nis_domain -> 40
    |`Nis_servers -> 41
    |`Ntp_servers -> 42
    |`Vendor_specific -> 43
    |`Netbios_name_server -> 44
    |`Netbios_dist_srv -> 45
    |`Netbios_node_type -> 46
    |`Netbios_scope -> 47
    |`X_window_font_server -> 48
    |`X_window_manager -> 49
    |`Requested_ip_address -> 50
    |`Requested_lease -> 51
    |`Option_overload -> 52
    |`Message_type -> 53
    |`Server_identifier -> 54
    |`Parameter_request -> 55
    |`Message -> 56
    |`Max_size -> 57
    |`Renewal_time -> 58
    |`Rebinding_time -> 59
    |`Vendor_class_id -> 60
    |`Client_identifier -> 61
    |`Netware_domain -> 62
    |`Netware_option -> 63
    |`Nis_domain_name -> 64
    |`Nis_server_addr -> 65
    |`Tftp_server_name -> 66
    |`Bootfile_name -> 67
    |`Mobile_ip_home_agent_addrs -> 68
    |`Smtp_server -> 69
    |`Pop3_server -> 70
    |`Nntp_server -> 71
    |`Www_server -> 72
    |`Finger_server -> 73
    |`Irc_server -> 74
    |`Streettalk_server -> 75
    |`Stda_server -> 76
    |`Domain_search -> 119
    |`End -> 255
    |`Unknown c -> Char.code c;;

  let to_byte x = Bytes.make 1 (Char.chr (t_to_code x))

  let uint32_to_bytes s =
    let x = Bytes.create 4 in
    let (>!) x y = Int32.logand (Int32.shift_right x y) 255l in
    Bytes.set x 0 (Char.chr (Int32.to_int (s >! 24)));
    Bytes.set x 1 (Char.chr (Int32.to_int (s >! 16)));
    Bytes.set x 2 (Char.chr (Int32.to_int (s >! 8)));
    Bytes.set x 3 (Char.chr (Int32.to_int (s >! 0)));
    x
  
  let uint16_to_bytes s =
    let x = Bytes.create 2 in
    Bytes.set x 0 (Char.chr (s land 255));
    Bytes.set x 1 (Char.chr ((s lsl 8) land 255)); (*??? WHY LEFT?*)
    x
  
  let uint16_list_to_bytes s =
    let x = List.map uint16_to_bytes s in
    Bytes.concat Bytes.empty x;;
    
  let uint8_to_bytes s =
    let x = Bytes.create 1 in
    Bytes.set x 0 (Char.chr (s land 255));
    x
  
  let bool_to_bytes b =
    if b then Bytes.make 1 (Char.chr 1)
    else Bytes.make 1 (Char.chr 0);;

  let size x = Bytes.make 1 (Char.chr x)
  let str c x = to_byte c :: (size (Bytes.length x)) :: [x]
  let uint32 c x = to_byte c :: [ "\004"; uint32_to_bytes x]
  let uint16 c x = to_byte c :: [ "\002"; uint16_to_bytes x]
  let uint8 c x = to_byte c :: [ "\001"; uint8_to_bytes x]
  let uint16_list c x =
    let len =  Bytes.make 1 (Char.chr (2*(List.length x))) in
    to_byte c :: [len;uint16_list_to_bytes x];;
  let boolean c x = to_byte c :: ["\001";bool_to_bytes x]
  let ip_list c ips =
    let x = List.map (fun x -> (uint32_to_bytes (Ipaddr.V4.to_int32 x))) ips in
    to_byte c :: (size (List.length x * 4)) :: x
  let ip_one c x = uint32 c (Ipaddr.V4.to_int32 x)

  let to_bytes (x:t) =
    let bits = match x with
      |`Pad -> [to_byte `Pad]
      |`Subnet_mask mask -> ip_one `Subnet_mask mask
      |`Time_offset _ -> assert false (* TODO 2s complement not uint32 *)
      |`Router ips -> ip_list `Router ips
      |`Time_server ips -> ip_list `Time_server ips
      |`Name_server ips -> ip_list `Name_server ips
      |`Dns_server ips -> ip_list `Dns_server ips
      |`Log_server ips -> ip_list `Log_server ips
      |`Cookie_server ips -> ip_list `Cookie_server ips
      |`Lpr_server ips -> ip_list `Lpr_server ips
      |`Impress_server ips -> ip_list `Impress_server ips
      |`Rlp_server ips -> ip_list `Rlp_server ips
      |`Hostname h -> str `Hostname h
      |`Boot_file_size b -> uint16 `Boot_file_size b
      |`Merit_dump_file m -> str `Merit_dump_file m
      |`Domain_name n -> str `Domain_name n
      |`Swap_server s -> ip_one `Swap_server s
      |`Root_path s -> str `Root_path s
      |`Extensions_path e -> str `Extensions_path e
      |`Ip_forwarding i -> boolean `Ip_forwarding i
      |`Non_local_source_routing n -> boolean `Non_local_source_routing n
      (*TODO: policy filter*)
      |`Max_datagram_reassembly d -> uint16 `Max_datagram_reassembly d
      |`Default_ip_ttl t -> uint8 `Default_ip_ttl t
      |`Mtu_timeout t -> uint32 `Mtu_timeout t
      |`Mtu_plateau p -> uint16_list `Mtu_plateau p
      |`Mtu_interface s -> uint16 `Mtu_interface s
      |`All_subnets_local s -> boolean `All_subnets_local s
      |`Broadcast_address ip -> ip_one `Broadcast_address ip
      |`Mask_discovery m -> boolean `Mask_discovery m
      |`Mask_supplier m -> boolean `Mask_supplier m
      |`Router_discovery r -> boolean `Router_discovery r
      |`Router_request r -> ip_one `Router_request r
      (*TODO: static route*)
      |`Trailers t -> boolean `Trailers t
      |`Arp_timeout a -> uint32 `Arp_timeout a
      |`Ethernet e -> boolean `Ethernet e
      |`Default_tcp_ttl t -> uint8 `Default_tcp_ttl t
      |`Keepalive_time t -> uint32 `Keepalive_time t
      |`Keepalive_data d -> boolean `Keepalive_data d
      |`Nis_domain d -> str `Nis_domain d
      |`Nis_servers s -> ip_list `Nis_domain s
      |`Ntp_servers s -> ip_list `Ntp_servers s
      |`Netbios_name_server ips -> ip_list `Netbios_name_server ips
      |`Netbios_dist_srv ips -> ip_list `Netbios_dist_srv ips
      |`Netbios_node_type n -> uint8 `Netbios_node_type n
      |`X_window_font_server x -> ip_one `X_window_font_server x
      |`X_window_manager x -> ip_one `X_window_manager x
      |`Requested_ip_address ip -> ip_one `Requested_ip_address ip
      |`Requested_lease t -> uint32 `Requested_lease t
      |`Option_overload o -> uint8 `Option_overload o
      |`Message_type mtype ->
        let mcode = function
          |`Discover -> "\001"
          |`Offer -> "\002"
          |`Request -> "\003"
          |`Decline -> "\004"
          |`Ack -> "\005"
          |`Nak -> "\006"
          |`Release -> "\007"
          |`Inform -> "\008"
          |`Unknown x -> Bytes.make 1 x in
        to_byte `Message_type :: "\001" :: [mcode mtype]
      |`Server_identifier id -> ip_one `Server_identifier id
      |`Parameter_request ps ->
        to_byte `Parameter_request :: (size (List.length ps)) ::
        List.map to_byte ps
      |`Message x -> str `Message x
      |`Max_size s -> uint16 `Max_size s
      |`Renewal_time r -> uint32 `Renewal_time r
      |`Rebinding_time r -> uint32 `Rebinding_time r
      |`Client_identifier s ->
        let s' = "\000" ^ s in (* only support domain name ids ???? *)
        str `Client_identifier s'
      |`Netware_domain n -> str `Netware_domain n
      |`Nis_domain_name n -> str `Nis_domain_name n
      |`Nis_server_addr n -> ip_list `Nis_server_addr n
      |`Mobile_ip_home_agent_addrs m -> ip_list `Mobile_ip_home_agent_addrs m
      |`Smtp_server s -> ip_list `Smtp_server s
      |`Pop3_server s -> ip_list `Pop3_server s
      |`Nntp_server s -> ip_list `Nntp_server s
      |`Www_server s -> ip_list `Www_server s
      |`Finger_server s -> ip_list `Finger_server s
      |`Irc_server s -> ip_list `Irc_server s
      |`Streettalk_server s -> ip_list `Streettalk_server s
      |`Stda_server s -> ip_list `Stda_server s 
      |`Domain_search _ ->
        assert false (* not supported yet, requires annoying Dns compression *)
      |`End -> [to_byte `End]
      |`Unknown (c,x) -> [ (Bytes.make 1 c); x ]
    in Bytes.concat "" bits

  let options mtype xs =
    let buf = Bytes.make 312 '\000' in
    let p = Bytes.concat "" (List.map to_bytes (`Message_type mtype :: xs @ [`End])) in
    (* DHCP packets have minimum length, hence the blit into buf *)
    Bytes.blit p 0 buf 0 (Bytes.length p);
    buf
end

module Unmarshal = struct

  exception Error of string

  let msg_of_code x : msg =
    match x with
    |'\000' -> `Pad
    |'\001' -> `Subnet_mask
    |'\002' -> `Time_offset
    |'\003' -> `Router
    |'\004' -> `Time_server
    |'\005' -> `Name_server
    |'\006' -> `Dns_server
    |'\007' -> `Log_server
    |'\008' -> `Cookie_server
    |'\009' -> `Lpr_server
    |'\010' -> `Impress_server
    |'\011' -> `Rlp_server
    |'\012' -> `Hostname
    |'\013' -> `Boot_file_size
    |'\014' -> `Merit_dump_file
    |'\015' -> `Domain_name
    |'\016' -> `Swap_server
    |'\017' -> `Root_path
    |'\018' -> `Extensions_path
    |'\019' -> `Ip_forwarding
    |'\020' -> `Non_local_source_routing
    |'\021' -> `Policy_filter
    |'\022' -> `Max_datagram_reassembly
    |'\023' -> `Default_ip_ttl
    |'\024' -> `Mtu_timeout
    |'\025' -> `Mtu_plateau
    |'\026' -> `Mtu_interface
    |'\027' -> `All_subnets_local
    |'\028' -> `Broadcast_address
    |'\029' -> `Mask_discovery
    |'\030' -> `Mask_supplier
    |'\031' -> `Router_discovery
    |'\032' -> `Router_request
    |'\033' -> `Static_route
    |'\034' -> `Trailers
    |'\035' -> `Arp_timeout
    |'\036' -> `Ethernet
    |'\037' -> `Default_tcp_ttl
    |'\038' -> `Keepalive_time
    |'\039' -> `Keepalive_data
    |'\040' -> `Nis_domain
    |'\041' -> `Nis_servers
    |'\042' -> `Ntp_servers
    |'\043' -> `Vendor_specific
    |'\044' -> `Netbios_name_server
    |'\045' -> `Netbios_dist_srv
    |'\046' -> `Netbios_node_type
    |'\047' -> `Netbios_scope
    |'\048' -> `X_window_font_server
    |'\049' -> `X_window_manager
    |'\050' -> `Requested_ip_address
    |'\051' -> `Requested_lease
    |'\052' -> `Option_overload
    |'\053' -> `Message_type
    |'\054' -> `Server_identifier
    |'\055' -> `Parameter_request
    |'\056' -> `Message
    |'\057' -> `Max_size
    |'\058' -> `Renewal_time
    |'\059' -> `Rebinding_time
    |'\060' -> `Vendor_class_id
    |'\061' -> `Client_identifier
    |'\062' -> `Netware_domain
    |'\063' -> `Netware_option
    |'\064' -> `Nis_domain_name
    |'\065' -> `Nis_server_addr
    |'\066' -> `Tftp_server_name
    |'\067' -> `Bootfile_name
    |'\068' -> `Mobile_ip_home_agent_addrs
    |'\069' -> `Smtp_server
    |'\070' -> `Pop3_server
    |'\071' -> `Nntp_server
    |'\072' -> `Www_server
    |'\073' -> `Finger_server
    |'\074' -> `Irc_server
    |'\075' -> `Streettalk_server
    |'\076' -> `Stda_server
    |'\119' -> `Domain_search
    |'\255' -> `End
    |x -> `Unknown x

  let of_bytes buf : t list =
    let pos = ref 0 in
    let getc () =  (* Get one character *)
      let r = Bytes.get buf !pos in
      pos := !pos + 1;
      r in
    let getint () = (* Get one integer *)
      Char.code (getc ()) in
    let slice len = (* Get a substring *)
      if (!pos + len) > (Bytes.length buf) || !pos > (Bytes.length buf)
      then raise (Error (sprintf "Requested too much string at %d %d (%d)" !pos len (Bytes.length buf) ));
      let r = Bytes.sub buf !pos len in
      pos := !pos + len;
      r in
    let check c = (* Check that a char is the provided value *)
      let r = getc () in
      if r != c then raise (Error (sprintf "check failed at %d != %d" !pos (Char.code c))) in
    let get_addr fn = (* Get 4 bytes, use for address or int32 *)
      check '\004';
      fn (slice 4) in
    let get_number len = (* Get a number from len bytes *)
      let bytestring = slice len in
      let r = ref 0 in
      for i = 0 to (len - 1) do
        let bitshift = ((len - (i + 1)) * 8) in
        r := ((Char.code bytestring.[i]) lsl bitshift) + !r;
      done;
      !r in
    let get_addrs fn = (* Repeat fn n times and return the list *)
      let len = getint () / 4 in
      let res = ref [] in
      for _i = 1 to len do
        res := (fn (slice 4)) :: !res
      done;
      List.rev !res in
    let uint32_of_bytes x =
      let fn p = Int32.shift_left (Int32.of_int (Char.code x.[p])) ((3-p)*8) in
      let (++) = Int32.add in
      (fn 0) ++ (fn 1) ++ (fn 2) ++ (fn 3) in
    let bool_of_bytes ()=
      check '\001';
      getint() = 1
    in
    let rec fn acc =
      let cont (r:t) = fn (r :: acc) in
      let code = msg_of_code (getc ()) in
      match code with
      |`Pad -> fn acc
      |`Subnet_mask -> cont (`Subnet_mask (get_addr ipv4_addr_of_bytes))
      |`Time_offset -> cont (`Time_offset (get_addr (fun x -> x)))
      |`Router -> cont (`Router (get_addrs ipv4_addr_of_bytes))
      |`Time_server -> cont (`Time_server (get_addrs ipv4_addr_of_bytes))
      |`Name_server -> cont (`Name_server (get_addrs ipv4_addr_of_bytes))
      |`Dns_server -> cont (`Dns_server (get_addrs ipv4_addr_of_bytes))
      |`Log_server -> cont (`Log_server (get_addrs ipv4_addr_of_bytes))
      |`Cookie_server -> cont (`Cookie_server (get_addrs ipv4_addr_of_bytes))
      |`Lpr_server -> cont (`Lpr_server (get_addrs ipv4_addr_of_bytes))
      |`Impress_server -> cont (`Impress_server (get_addrs ipv4_addr_of_bytes))
      |`Rlp_server -> cont (`Rlp_server (get_addrs ipv4_addr_of_bytes))
      |`Hostname -> cont (`Hostname (slice (getint ())))
      |`Domain_name -> cont (`Domain_name (slice (getint ())))
      |`Swap_server -> cont (`Swap_server (get_addr ipv4_addr_of_bytes))
      |`Root_path -> cont (`Root_path (slice(getint())))
      |`Extensions_path -> cont (`Extensions_path (slice(getint())))
      |`Ip_forwarding -> cont(`Ip_forwarding (bool_of_bytes()))
      |`Non_local_source_routing -> cont(`Non_local_source_routing (bool_of_bytes()))
      |`Mtu_timeout -> cont(`Mtu_timeout(get_addr uint32_of_bytes))
      |`Mtu_interface ->
        (* TODO according to some printf/tcpdump testing, this is being set but not
         * respected by the unikernel; https://github.com/mirage/mirage/issues/238 *)
        let len = getint () in
        cont (`Mtu_interface (get_number len))
      |`All_subnets_local -> cont(`All_subnets_local (bool_of_bytes ()))
      |`Broadcast_address -> cont (`Broadcast_address (get_addr ipv4_addr_of_bytes))
      |`Router_request -> cont (`Router_request (get_addr ipv4_addr_of_bytes))
      (*TODO: static routes,trailers*)
      |`Arp_timeout -> cont (`Arp_timeout (get_addr uint32_of_bytes))
      (*TODO: ethernet,default tcp ttl*)
      |`Keepalive_time -> cont (`Keepalive_time (get_addr uint32_of_bytes))
      (*TODO:keepalive data*)
      |`Nis_domain -> cont (`Nis_domain (slice(getint())))
      |`Nis_servers -> cont (`Nis_servers (get_addrs ipv4_addr_of_bytes))
      |`Ntp_servers -> cont (`Ntp_servers (get_addrs ipv4_addr_of_bytes))
      |`Netbios_name_server -> cont (`Netbios_name_server (get_addrs ipv4_addr_of_bytes))
      |`Netbios_dist_srv -> cont (`Netbios_dist_srv (get_addrs ipv4_addr_of_bytes))
      (*TODO: netbios node type*)
      |`X_window_font_server -> cont (`X_window_font_server (get_addr ipv4_addr_of_bytes))
      |`X_window_manager -> cont (`X_window_manager (get_addr ipv4_addr_of_bytes))
      |`Requested_ip_address -> cont (`Requested_ip_address (get_addr ipv4_addr_of_bytes))
      |`Requested_lease -> cont (`Requested_lease (get_addr uint32_of_bytes))
      (*TODO: option overload*)
      |`Message_type ->
        check '\001';
        let mcode = match (getc ()) with
          |'\001' -> `Discover
          |'\002' -> `Offer
          |'\003' -> `Request
          |'\004' -> `Decline
          |'\005' -> `Ack
          |'\006' -> `Nak
          |'\007' -> `Release
          |'\008'  -> `Inform
          |x -> `Unknown x in
        cont (`Message_type mcode)
      |`Server_identifier -> cont (`Server_identifier (get_addr ipv4_addr_of_bytes))
      |`Parameter_request ->
        let len = getint () in
        let params = ref [] in
        for _i = 1 to len do
          params := (msg_of_code (getc ())) :: !params
        done;
        cont (`Parameter_request (List.rev !params))
      |`Message -> cont (`Message (slice (getint ())))
      |`Max_size ->
        let len = getint () in
        cont (`Max_size (get_number len))
      |`Renewal_time -> cont (`Renewal_time (get_addr uint32_of_bytes))
      |`Rebinding_time -> cont (`Rebinding_time (get_addr uint32_of_bytes))
      |`Client_identifier ->
        let len = getint () in
        let _ = getint () in (* disregard type information *)
        cont (`Client_identifier (slice len))
      |`Netware_domain -> cont (`Netware_domain (slice (getint())))
      |`Nis_domain_name -> cont (`Nis_domain_name (slice(getint())))
      |`Nis_server_addr -> cont (`Nis_server_addr (get_addrs ipv4_addr_of_bytes))
      |`Mobile_ip_home_agent_addrs -> cont (`Mobile_ip_home_agent_addrs (get_addrs ipv4_addr_of_bytes))
      |`Smtp_server -> cont (`Smtp_server (get_addrs ipv4_addr_of_bytes))
      |`Pop3_server -> cont (`Pop3_server (get_addrs ipv4_addr_of_bytes))
      |`Www_server -> cont (`Www_server (get_addrs ipv4_addr_of_bytes))
      |`Finger_server -> cont (`Finger_server (get_addrs ipv4_addr_of_bytes))
      |`Irc_server -> cont (`Irc_server (get_addrs ipv4_addr_of_bytes))
      |`Streettalk_server -> cont (`Streettalk_server (get_addrs ipv4_addr_of_bytes))
      |`Stda_server -> cont (`Stda_server (get_addrs ipv4_addr_of_bytes))
      |`Domain_search -> cont (`Domain_search (slice (getint())))
      |`End -> acc
      |`Unknown c -> cont (`Unknown (c, (slice (getint ()))))
    in
    fn []
end

module Packet = struct
  type p  = {
    op: op;
    opts: t list;
  }

  let of_bytes buf =
    let opts = Unmarshal.of_bytes buf in
    let mtype, rest = List.partition (function `Message_type _ -> true |_ -> false) opts in
    let op = match mtype with [ `Message_type m ] -> m |_ -> raise (Unmarshal.Error "no mtype") in
    { op=op; opts=rest }

  let to_bytes p =
    Marshal.options p.op p.opts

  let prettyprint t =
    sprintf "%s : %s" (op_to_string t.op) (String.concat ", " (List.map t_to_string t.opts))

  (* Find an option in a packet *)
  let find p fn =
    List.fold_left (fun a b ->
        match fn b with
        |Some x -> Some x
        |None -> a) None p.opts

  (* Find an option list, and return empty list if opt doesnt exist *)
  let findl p fn =
    match find p fn with
    |Some l -> l
    |None -> []
end
