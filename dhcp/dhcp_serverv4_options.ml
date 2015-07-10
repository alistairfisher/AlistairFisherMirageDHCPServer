open Dhcpv4_option.Packet;;

let rec parameter_request c_requests s_parameters = match c_requests with
  |[]->[]
  |(h::t) -> List.assoc h s_parameters :: (parameter_request t s_parameters);;


  let options ~parameters_list ~client_requests ~serverIP ~lease_length ~message_type = 
    { op = message_type; opts= [`Lease_time lease_length;`Server_identifier serverIP; `End]};;