(*
 * Copyright (c) 2006-2011 Anil Madhavapeddy <anil@recoil.org>
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

type op =
  [ `Ack
  | `Decline
  | `Discover
  | `Inform
  | `Nak
  | `Offer
  | `Release
  | `Request
  | `Unknown of char ]
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
val t_equal_to_msg : t -> msg -> bool
val msg_to_string : msg -> string
val op_to_string : op -> string
val t_to_string : t -> string
val ipv4_addr_of_bytes : string -> Ipaddr.V4.t
module Marshal :
sig
  val t_to_code : msg -> int
  val to_byte : msg -> string
  val uint32_to_bytes : int32 -> string
  val uint16_to_bytes : int -> string
  val size : int -> string
  val ip_list : msg -> Ipaddr.V4.t list -> string list
  val ip_one : msg -> Ipaddr.V4.t -> string list
  val str : msg -> string -> string list
  val uint32 : msg -> int32 -> string list
  val uint16 : msg -> int -> string list
  val to_bytes : t -> string
  val options : op -> t list -> string
end
module Unmarshal :
sig
  exception Error of string
  val msg_of_code : char -> msg
  val of_bytes : string -> t list
end
module Packet :
sig
  type p = { op : op; opts : t list; }
  val of_bytes : string -> p
  val to_bytes : p -> string
  val prettyprint : p -> string
  val find : p -> (t -> 'a option) -> 'a option
  val findl : p -> (t -> 'a list option) -> 'a list
end
