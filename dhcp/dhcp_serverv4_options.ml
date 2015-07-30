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

open Dhcpv4_option;;
open Dhcpv4_option.Packet;;

let t_equalto_msg t msg = (*options in general need a better implementation, functions like this need to handle 255 cases separately...*)
  match t,msg with
  |`Subnet_mask _,`Subnet_mask -> true
  |`Time_offset _,`Time_offset-> true
  |`Router _,`Router ->true
  |`Broadcast _,`Broadcast -> true
  |`Time_server _,`Time_server -> true
  |`Name_server _,`Name_server -> true
  |`DNS_server _,`DNS_server -> true
  |`Netbios_name_server _,`Netbios_name_server -> true
  |`Host_name _,`Host_name -> true
  |`Domain_name _,`Domain_name -> true
  |`Requested_ip _,`Requested_ip -> true
  |`Message_type _,`Message_type -> true
  |`Server_identifier _,`Server_identifier-> true
  |`Interface_mtu _,`Interface_mtu -> true
  |`Message _,`Message -> true
  |`Max_size _,`Max_size -> true
  |`Client_id _,`Client_id -> true
  |`Domain_search _,`Domain_search -> true
  |_ -> false

let rec find_option option parameter_list =
  match parameter_list with
  |[] -> None
  |h::t ->
    if t_equalto_msg h option then Some h
    else find_option option t;;

let rec parameter_request c_requests s_parameters = match c_requests with
  |[]->[]
  |(h::t) ->
    let option = find_option h s_parameters in
    match option with
    |None -> parameter_request t s_parameters
    |Some o -> o::(parameter_request t s_parameters);;

let filter_client_requests c = 
  let filter x = (x<>`Subnet_mask) && (x<>`Pad) && (x<>`End) && (x<>`Lease_time) && (x<>`Parameter_request) in (*Filter out padding, End, and subnet_mask and lease_time because these 2 are found separately*)
(*TODO: remove duplicated from client requests*)
  List.filter filter c;;
    
let make_options_no_lease ~client_requests ~server_parameters ~serverIP ~message_type =
  let filtered_client_requests = filter_client_requests client_requests in
  let params = parameter_request filtered_client_requests server_parameters in
  if (List.mem `Subnet_mask client_requests) then (*It is crucial that subnet mask be at the head of the list: RFC 2132 states that in an options 
  packet, subnet mask must be specified before routers.*)
    let subnet_mask = find_option `Subnet_mask server_parameters in
    match subnet_mask with
    |None -> { op = message_type; opts= (`Server_identifier serverIP)::params@[`End]}
    |Some s ->  { op = message_type; opts= [`Server_identifier serverIP;s]@params@[`End]}
  else { op = message_type; opts= (`Server_identifier serverIP)::params@[`End]};;

let make_options_lease2 ~client_requests ~server_parameters ~serverIP ~lease_length ~message_type =
  let options = make_options_no_lease client_requests server_parameters serverIP message_type in
  {op = options.op;opts = ((`Lease_time lease_length) :: options.opts)};;