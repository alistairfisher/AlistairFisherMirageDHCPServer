module Lease_state = struct
  type t = | Available | Reserved of (int32*Dhcp_serverv4_data_structures.client_identifier) | Active of Dhcp_serverv4_data_structures.client_identifier;; (*use the int32 to hold a reservations transaction id*)
  
  let of_string s = 
    try
      let tokens = String.split s ' ' in
      let lease_state = List.hd tokens in
      match lease_state with
      |"Available"-> Some Available
      |"Reserved" ->
        let xid = Int32.of_string (List.nth 1 tokens) in
        let client_id = (List.nth 2 tokens) in
        Some (Reserved xid client_id)
      |"Active" ->
        let client_id = (List.nth 2 tokens) in
        Some (Active client_id);;
    with
    | _ -> None
  
  let to_string = function
    |Available -> "Available"
    |Reserved xid client_identifier-> Prinf.sprintf "Reserved %s %s" (Int32.to_string xid) client_identifier
    |Active client_identifier-> Printf.sprintf "Active %s" client_identifier;;
    
  let compare x y = 0;;
  
end

module Entry = Inds_entry.Make(Lease_state)

module Table = Inds_table.Make(Ipaddr.V4)(Entry)(Irmin.Path.String_list)