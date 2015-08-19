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
    
  let compare x y = 0;;
  
end

module Entry = Inds_entry.Make(Lease_state)

module Table = Inds_table.Make(Ipaddr.V4)(Entry)(Irmin.Path.String_list)