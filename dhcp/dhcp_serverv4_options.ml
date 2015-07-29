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

let t_equalto_msg t msg = 
  let string_of_t = t_to_string t in
  let string_of_msg = msg_to_string msg in
  string_of_t = string_of_msg;;

let rec find_option option parameter_list =
  match parameter_list with
  |[] -> None
  |h::t ->
    if t_equalto_msg h option then Some h
    else find_option option t;;

let rec parameter_request c_requests s_parameters = match c_requests with (*This will cause searches for stuff the server can't provide like Parameter Request.
  It's still correct (provided the server parameters themselves don't contain strange parameters) but inefficient*)
  |[]->[]
  |(h::t) ->
    let option = find_option h s_parameters in
    match option with
    |None -> parameter_request t s_parameters
    |Some o -> o::(parameter_request t s_parameters);;


let make_options_lease ~client_requests ~server_parameters ~serverIP ~lease_length ~message_type =
  let params = parameter_request client_requests server_parameters in
  { op = message_type; opts= [`Lease_time lease_length;`Server_identifier serverIP]@params@[`End]};;
    
let make_options_no_lease ~client_requests ~server_parameters ~serverIP ~message_type =
  let params = parameter_request client_requests server_parameters in
  {op = message_type;opts = [`Server_identifier serverIP]@params@[`End]};;
    