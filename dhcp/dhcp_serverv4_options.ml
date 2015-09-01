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

let rec find_option option subnet_parameters global_parameters = 
  let rec find_option2 option parameter_list = (*Find an option in the list of subnet parameters*)
    match parameter_list with
    |[] -> None
    |h::t ->
      if t_equal_to_msg h option then Some h
      else find_option2 option t
  in
  match (find_option2 option subnet_parameters) with (*try subnet params first, if nothing found, try globals*)
  |Some x -> Some x
  |None -> find_option2 option global_parameters

let rec parameter_request c_requests s_parameters g_parameters = match c_requests with
  |[]->[]
  |(h::t) ->
    let option = find_option h s_parameters g_parameters in
    match option with
    |None -> parameter_request t s_parameters g_parameters
    |Some o -> o::(parameter_request t s_parameters g_parameters);;

let filter_client_requests c = (*certain requests are filtered, either because no direct response is intended (End, Pad, Parameter request, Requested_ip, lease length) or
  the direct response is provided elswhere (subnet mask) since it must be provided before routers*)
  let filter x = (x<>`Subnet_mask) && (x<>`Pad) && (x<>`End) && (x<>`Requested_lease) && (x<>`Parameter_request) && (x<>`Requested_ip_address) in
(*TODO: remove duplicates from client requests, this is necessary*)
  List.filter filter c;;
    
let make_options_without_lease ~client_requests ~subnet_parameters ~global_parameters ~serverIP ~message_type =
  let filtered_client_requests = filter_client_requests client_requests in
  let params = parameter_request filtered_client_requests subnet_parameters global_parameters in
  if (List.mem `Subnet_mask client_requests) then (*It is crucial that subnet mask be at the head of the list: RFC 2132 states that in an options 
  packet, subnet mask must be specified before routers.*)
    let subnet_mask = find_option `Subnet_mask subnet_parameters global_parameters in
    match subnet_mask with
    |None -> { op = message_type; opts= (`Server_identifier serverIP)::params@[`End]}
    |Some s ->  { op = message_type; opts= [`Server_identifier serverIP;s]@params@[`End]}
  else { op = message_type; opts= (`Server_identifier serverIP)::params@[`End]};;

let make_options_with_lease ~client_requests ~subnet_parameters ~global_parameters ~serverIP ~lease_length ~message_type =
  let options = make_options_without_lease client_requests subnet_parameters global_parameters serverIP message_type in
  {op = options.op;opts = ((`Requested_lease lease_length) :: options.opts)};;