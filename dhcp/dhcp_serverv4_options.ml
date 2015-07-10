open Dhcpv4_option.Packet;;

let rec parameter_request c_requests s_parameters = match c_requests with
  |[]->[]
  |(h::t) -> List.assoc h s_parameters :: (parameter_request t s_parameters);;


  let make_options ~client_requests ~serverIP ~lease_length ~message_type =
    (*let params = parameter_request ~c_requests:client requests ~s_parameters:parameters_list*) in 
    { op = message_type; opts= [`Lease_time lease_length;`Server_identifier serverIP;`End]};;