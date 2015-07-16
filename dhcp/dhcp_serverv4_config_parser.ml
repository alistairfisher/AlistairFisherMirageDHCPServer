open Core.Std

type parameters =
{
  default_lease_length: int32 ref;
  max_lease_length: int32 ref;
  scope_bottom: Ipaddr.V4.t ref;
  scope_top: Ipaddr.V4.t ref;
  parameters: Dhcp_v4_options.t list ref;
}

type server_parameters =
{
  globals: parameters;
  subnets: Ipaddr.V4.t*Ipaddr.V4.t*parameters
}

let read_DHCP_config = 
  let input_channel = open_in "/etc/dhcpd.conf" in
  read_globals input_channel;;

let rec read_globals input_channel =

  try
    let next_line = input_line input_channel in
    let tokens = Str.split " +" input_line in
    let first_token = List.nth tokens 0 in
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
      let scope_bottom = List.nth tokens 1 in
      let scope_top = List.nth tokens 2 in
      let current_options = read_globals input_channel in
      current_options.globals.scope_bottom := scope_bottom;
      current_options.globals.scope_top := scope_top;
      current_options
    |"default_lease_length" 
    
  with End_of_file -> ()

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
    |"ntp-servers"->`Time_server (strings_to_ip_addresses (List.tl tokens)) (*list TODO*)
    |"name-server"->`Name_server (strings_to_ip_addresses (List.tl tokens))
    |"domain-name-servers"->`DNS_server (strings_to_ip_addresses (List.tl tokens))
    |"netbios-name-servers"->`Netbios_name_server (strings_to_ip_addresses (List.tl tokens))
    |"domain-name" -> `Domain_name value
    |"default-lease-time" -> `Lease_time (Int32.of_string value) (*need to build new data structure*)
    |"max-lease-time" -> `Lease_time (Int32.of_string value)
    |_-> raise Unknown_option value

exception parsing_error of string (*TODO: add line numbers*)

let read_subnet_start tokens input_channel global_list =
  let subnet = Ipaddrv4.of_string(List.hd tokens) in
  match (List.nth 1 tokens),(List.nth 3 tokens) with
  |"netmask","{" ->
    let netmask = Ipaddrv4.of_string (List.nth 2) in
    let parameters = read_subnet input_channel in
    {subnet;netmask;parameters}
  |"netmask",_ -> raise parsing_error "{ expected after subnet declaration"
  |_,_ -> raise parsing_error "netmask not declared in subnet declaration"
  

let rec read_subnet input_channel=
  let next_line = input_line input_channel in
  let tokens = Str.split " +" input_line in
  let first_token = List.hd tokens in
  let value = List.nth 2 tokens in
  match first_token with
  |"}" -> [] (*end of subnet declaration*)
  |"option"-> (read_option tokens)::(read_subnet input_channel)
  |"range"->
  