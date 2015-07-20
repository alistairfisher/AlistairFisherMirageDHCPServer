open Core.Std.String

(*Parsing empty lines!!!*)

exception Parse_error of string;; (*should add line number*)

type working_parameters =
{
  default_lease_length: int32 option ref;
  max_lease_length: int32 option ref;
  scope_bottom: Ipaddr.V4.t option ref;
  scope_top: Ipaddr.V4.t option ref;
  parameters: Dhcpv4_option.t list ref;
}

type working_server_parameters =
{
  globals: working_parameters;
  subnets: (Ipaddr.V4.t*Ipaddr.V4.t*working_parameters) list ref;
}

let cut_at_semicolon string =
  let semicolon_position = Core.Std.String.index string ';' in
  match semicolon_position with
  |Some x-> String.sub string 0 x
  |None -> string

let strings_to_ip_addresses list =
  List.map (Ipaddr.V4.of_string_exn) list;;
  
exception Unknown_option of string;;

let read_option tokens =
  let open Dhcpv4_option in
  try
    let dhcp_option = List.nth tokens 0 in
    let value = List.nth tokens 1 in
    match dhcp_option with
    |"subnet-mask"->`Subnet_mask (Ipaddr.V4.of_string_exn value)
    |"broadcast-address"->`Broadcast (Ipaddr.V4.of_string_exn value)
    |"time-offset"->`Time_offset value
    |"routers"->`Router (strings_to_ip_addresses (List.tl tokens))
    |"ntp-servers"->`Time_server (strings_to_ip_addresses (List.tl tokens))
    |"name-server"->`Name_server (strings_to_ip_addresses (List.tl tokens))
    |"domain-name-servers"->`DNS_server (strings_to_ip_addresses (List.tl tokens))
    |"netbios-name-servers"->`Netbios_name_server (strings_to_ip_addresses (List.tl tokens))
    |"domain-name" -> `Domain_name value
    |"default-lease-time" -> `Lease_time (Int32.of_string value)
    |"max-lease-time" -> `Lease_time (Int32.of_string value)
    |_-> raise (Unknown_option value)
  with
  |(Ipaddr.Parse_error _) -> raise (Parse_error "Invalid option: misformatted ip address") (*TODO: use sprintf to report the incorrect option*)
  |(Failure _) -> raise (Parse_error "No enough arguments for option")

exception Undefined_range_for_subnet of string;;
  
let rec read_subnet input_channel=
  let next_line = cut_at_semicolon(input_line input_channel) in
  let separator = Str.regexp " +" in
  let tokens = Str.split separator next_line in
  try
    let first_token = List.hd tokens in
    match first_token with
    |"}" -> {default_lease_length = ref None;max_lease_length = ref None;scope_bottom = ref None;scope_top = ref None;parameters = ref []} (*end of subnet declaration*)
    |"option"->
      let new_option = read_option (List.tl tokens) in
      let current_subnet_parameters = read_subnet input_channel in
      current_subnet_parameters.parameters:= new_option::(!(current_subnet_parameters.parameters));
      current_subnet_parameters
    |"range"->
      let scope_bottom = (Ipaddr.V4.of_string (List.nth tokens 1)) in
      let scope_top = (Ipaddr.V4.of_string (List.nth tokens 2)) in
      let current_subnet_parameters = read_subnet input_channel in
      current_subnet_parameters.scope_bottom:= scope_bottom;
      current_subnet_parameters.scope_top:= scope_top;
      current_subnet_parameters
    |"default_lease_length" ->
      let value = List.nth tokens 1 in
      let lease_length = Int32.of_string value in
      let current_options = read_subnet input_channel in
      current_options.default_lease_length := Some lease_length;
      current_options
    |"max_lease_length" ->
      let value = List.nth tokens 1 in
      let lease_length = Int32.of_string value in
      let current_options = read_subnet input_channel in
      current_options.max_lease_length := Some lease_length;
      current_options
  with
  |(Failure _) -> raise (Parse_error "Insufficient arguments)")
  
(*
let rec read_group input_channel = 
  let next_line = cut_at_semicolon(input_line input_channel) in
  let tokens = Str.split " +" next_line in
  let first_token = List.hd tokens in
  let value = List.nth 1 tokens in
  match first_token with
*)

  let read_subnet_start tokens input_channel =
    try
      let subnet = Ipaddr.V4.of_string_exn(List.hd tokens) in
      match (List.nth tokens 1),(List.nth tokens 3) with
      |"netmask","{" -> (*correct netmask declaration, keep parsing*)
        (let netmask = Ipaddr.V4.of_string_exn (List.nth tokens 2) in
        let parameters = read_subnet input_channel in
        (*check that scope is defined*)
        match !(parameters.scope_bottom) with
          |None-> raise (Undefined_range_for_subnet (List.hd tokens))
          |Some x->  subnet,netmask,parameters)
      |"netmask",_ -> raise (Parse_error "'{' expected after subnet declaration")
      |_,_ -> raise (Parse_error "netmask not declared in subnet declaration")
    with
    |(Ipaddr.Parse_error _) -> raise (Parse_error "Invalid subnet mask")
    |(Failure _) -> raise (Parse_error "Not enough arguments in subnet declaration")

  let rec read_globals input_channel =

    try
      let next_line = cut_at_semicolon(input_line input_channel) in
      let separator = Str.regexp " +" in
      let tokens = Str.split separator next_line in
      let first_token = List.nth tokens 0 in
      match first_token with
      |"#" -> read_globals input_channel(*comment:ignore line*)
      |"subnet" ->
        let new_subnet = read_subnet_start (List.tl tokens) input_channel in
        let current_options = (read_globals input_channel) in
        current_options.subnets := new_subnet::(!(current_options.subnets));
        current_options
      (*|"group" -> read_group_start (List.tl tokens) global_parameters*)
      |"option" ->
        let new_option = read_option (List.tl tokens) in
        let current_options = read_globals input_channel in
        current_options.globals.parameters := new_option::(!(current_options.globals.parameters));
        current_options
      |"range" ->
        let scope_bottom = Ipaddr.V4.of_string (List.nth tokens 1) in
        let scope_top = Ipaddr.V4.of_string (List.nth tokens 2) in
        let current_options = read_globals input_channel in
        current_options.globals.scope_bottom := scope_bottom;
        current_options.globals.scope_top := scope_top;
        current_options
      |"default_lease_length" ->
        (try
          let value = List.nth tokens 1 in
          let lease_length = Some (Int32.of_string value) in
          let current_options = read_globals input_channel in
          current_options.globals.default_lease_length := lease_length;
          current_options
        with
        |(Failure _) -> raise (Parse_error "No valid argument for max lease length")
      )
      |"max_lease_length" ->
        try
          let value = List.nth tokens 1 in
          let lease_length = Some (Int32.of_string value) in
          let current_options = read_globals input_channel in
          current_options.globals.max_lease_length := lease_length;
          current_options
        with
          |(Failure _) -> raise (Parse_error "No argument for max lease length")
    with
    |End_of_file ->
      {globals = {default_lease_length=ref None;max_lease_length = ref None;scope_bottom = ref None;scope_top = ref None;parameters = ref []};subnets=ref[]}

let read_DHCP_config = 
  let input_channel = open_in "/etc/dhcpd.conf" in
  read_globals input_channel;;
    
    
  