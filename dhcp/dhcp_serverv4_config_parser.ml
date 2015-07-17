open Core.Std

type parameters =
{
  default_lease_length: int32 option ref;
  max_lease_length: int32 option ref;
  scope_bottom: Ipaddr.V4.t option ref;
  scope_top: Ipaddr.V4.t option ref;
  parameters: Dhcp_v4_options.t list ref;
}

type server_parameters =
{
  globals: parameters;
  subnets: (Ipaddr.V4.t*Ipaddr.V4.t*parameters) list ref;
}

let read_DHCP_config = 
  let input_channel = open_in "/etc/dhcpd.conf" in
  read_globals input_channel;;

let cut_at_semicolon string =
  try
    let semicolon_position = String.index string ';' in
    String.sub string 0 semicolon_position
  with String.Not_found -> string;;
 
let rec read_globals input_channel =

  try
    let next_line = cut_at_semicolon(input_line input_channel) in
    let tokens = Str.split " +" input_line in
    let first_token = List.nth tokens 0 in
    let value = List.nth tokens 1 in
    match first_token with
    |"#" -> read_globals input_channel(*comment:ignore line*)
    |"subnet" ->
      let new_subnet = read_subnet_start (List.tl tokens) global_parameters in
      current_options.subnets := new_subnet(!currentoptions.subnets);
      current_options
    |"group" -> read_group_start (List.tl tokens) global_parameters
    |"option" ->
      let new_option = read_option (List.tl tokens) in
      let current_options = read_globals input_channel in
      current_options.parameters := new_option::(!(current_options.globals.parameters));
      current_options
    |"range" ->
      let scope_bottom = Some (List.nth tokens 1) in
      let scope_top = Some (List.nth tokens 2) in
      let current_options = read_globals input_channel in
      current_options.globals.scope_bottom := scope_bottom;
      current_options.globals.scope_top := scope_top;
      current_options
    |"default_lease_length" ->
      let lease_length = Int32.of_string value in
      let current_options = read_globals input_channel in
      currentoptions.globals.default_lease_length := lease_length;
      current_options
    |"max_lease_length" ->
      let lease_length = Int32.of_string value in
      let current_options = read_globals input_channel in
      currentoptions.globals.max_lease_length := lease_length;
      current_options
    
  with
  |End_of_file ->
    {globals = {default_lease_length=ref None;max_lease_length = ref None;scope_bottom = ref None;scope_bottom = ref None;parameters = ref []};subnets=ref[]}

let strings_to_ip_addresses list =
  map (Ipaddrv4.of_string) list;;
  
exception Unknown_option of string;;

let read_option tokens =
  let open Dhcp_v4_options in
  let dhcp_option = List.nth tokens 0 in
  let value = List.nth tokens 1 in
  match dhcp_option with
    |"subnet-mask"->`Subnet_mask (Ipaddrv4.of_string value)
    |"broadcast-address"->`Broadcast (Ipaddrv4.of_string value)
    |"time-offset"->`Time_offset value
    |"routers"->`Router (strings_to_ip_addresses (List.tl tokens))
    |"ntp-servers"->`Time_server (strings_to_ip_addresses (List.tl tokens))
    |"name-server"->`Name_server (strings_to_ip_addresses (List.tl tokens))
    |"domain-name-servers"->`DNS_server (strings_to_ip_addresses (List.tl tokens))
    |"netbios-name-servers"->`Netbios_name_server (strings_to_ip_addresses (List.tl tokens))
    |"domain-name" -> `Domain_name value
    |"default-lease-time" -> `Lease_time (Int32.of_string value)
    |"max-lease-time" -> `Lease_time (Int32.of_string value)
    |_-> raise Unknown_option value;;

exception Parsing_error of string;; (*TODO: add line numbers*)
exception Undefined_range_for_subnet of string;;

let read_subnet_start tokens input_channel global_list =
  let subnet = Ipaddrv4.of_string(List.hd tokens) in
  match (List.nth 1 tokens),(List.nth 3 tokens) with
  |"netmask","{" ->
    (let netmask = Ipaddrv4.of_string (List.nth 2) in
    let parameters = read_subnet input_channel in
    (*check that scope is defined*)
    match !(parameters.scope_bottom) with
      |None-> raise undefined_range_for_subnet (List.hd tokens)
      |Some x->  subnet,netmask,parameters)
  |"netmask",_ -> raise parsing_error "{ expected after subnet declaration"
  |_,_ -> raise parsing_error "netmask not declared in subnet declaration"
  

let rec read_subnet input_channel=
  let next_line = cut_at_semicolon(input_line input_channel) in
  let tokens = Str.split " +" next_line in
  let first_token = List.hd tokens in
  let value = List.nth 1 tokens in
  match first_token with
  |"}" -> {default_lease_length = ref None;max_lease_length = ref None;scope_bottom = ref None;scope_top = ref None;parameters = ref []} (*end of subnet declaration*)
  |"option"->
    let new_option = read_option value in
    let current_subnet_parameters = read_subnet input_channel in
    current_subnet_parameters.parameters:= new_option::(!current_subnet_parameters.parameters);
    current_subnet_parameters    
  |"range"->
    let scope_bottom = Some (Ipaddr.V4.of_string (List.nth tokens 1)) in
    let scope_top = Some (Ipaddr.V4.of_string (List.nth tokens 2)) in
    let current_subnet_parameters = read_subnet input_channel in
    current_subnet_parameters.scope_bottom:= scope_bottom;
    current_subnet_parameters.scope_top:= scope_top;
    current_subnet_parameters
  |"default_lease_length" ->
    let lease_length = Int32.of_string value in
    let current_options = read_subnet input_channel in
    currentoptions.default_lease_length := lease_length;
    current_options
  |"max_lease_length" ->
    let lease_length = Int32.of_string(List.nth tokens 1) in
    let current_options = read_subnet input_channel in
    currentoptions.max_lease_length := lease_length;
    current_options
    
(*
let rec read_group input_channel = 
  let next_line = cut_at_semicolon(input_line input_channel) in
  let tokens = Str.split " +" next_line in
  let first_token = List.hd tokens in
  let value = List.nth 1 tokens in
  match first_token with
*)
      
    
    
  