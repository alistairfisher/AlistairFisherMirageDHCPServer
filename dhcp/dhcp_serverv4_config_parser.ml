open Core.Std.String

exception Parse_error of string;;

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

type host_configuration = 
{
  hardware_address: string option ref;
  ip_address: Ipaddr.V4.t option ref; 
  host_parameters: Dhcpv4_option.t list ref;
}

let strings_to_ip_addresses list =
  let no_commas = List.map (Str.global_replace (Str.regexp ",") "") list in
  List.map (Ipaddr.V4.of_string_exn) no_commas;;  

let generate_error_message message line_number = 
  Printf.sprintf "%s on line %d" message line_number;;

let read_option tokens line_number =
  let open Dhcpv4_option in
  match tokens with
  |[] -> let error_message = generate_error_message "No option specified" line_number in
    raise(Parse_error error_message)
  |_ ->
    let dhcp_option = List.nth tokens 0 in
    try
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
      |"domain-search" -> `Domain_search value
      |_->
        let error_message = generate_error_message "Unknown DHCP option" line_number in
        raise (Parse_error error_message)
    with
    |(Ipaddr.Parse_error _) ->
      let error_message = generate_error_message "Invalid ip address" line_number in
      raise (Parse_error error_message)
    |(Failure m) ->
      (match m with
      |"nth" ->
        let error_message = generate_error_message ("Insufficient arguments for option "^dhcp_option) line_number in
        raise (Parse_error error_message)
      |"int_of_string" ->
        let error_message = generate_error_message ("Argument for parameter "^dhcp_option^" must be an integer") line_number in
        raise (Parse_error error_message)
      |_ ->
        let error_message = generate_error_message "Parsing error on line" line_number in
        raise (Parse_error error_message)
      );;
  
let rec read_subnet declarations =
  match declarations with
  |[]->
    let error_message = "Final subnet is not completed, } expected" in
    raise (Parse_error error_message)
  |(dec,line_number)::tail ->
    try
      let first_token = List.hd dec in
      let rest_of_dec = List.tl dec in
      match first_token with
      |"}" -> {default_lease_length = ref None;max_lease_length = ref None;scope_bottom = ref None;scope_top = ref None;parameters = ref []},tail (*end of subnet declaration*)
      |"option"->
        let new_option = read_option rest_of_dec line_number in
        let current_subnet_parameters,d = read_subnet tail in
        current_subnet_parameters.parameters:= new_option::(!(current_subnet_parameters.parameters));
        (current_subnet_parameters),d
      |"range"->
        let scope_bottom = (Ipaddr.V4.of_string (List.nth rest_of_dec 0)) in
        let scope_top = (Ipaddr.V4.of_string (List.nth rest_of_dec 1)) in
        let current_subnet_parameters,d = read_subnet tail in
        current_subnet_parameters.scope_bottom:= scope_bottom;
        current_subnet_parameters.scope_top:= scope_top;
        current_subnet_parameters,d
      |"default_lease_time" ->
        let value = List.hd rest_of_dec in
        let lease_length = Int32.of_string value in
        let current_options,d = read_subnet tail in
        current_options.default_lease_length := Some lease_length;
        current_options,d
      |"max_lease_time" ->
        let value = List.hd rest_of_dec in
        let lease_length = Int32.of_string value in
        let current_options,d = read_subnet tail in
        current_options.max_lease_length := Some lease_length;
        current_options,d
      |_ ->
        let error_message = generate_error_message ("Unknown subnet parameter " ^ first_token) line_number in
        raise (Parse_error error_message)
  with
  |(Failure "hd") ->
    let error_message = generate_error_message "Blank declaration " line_number in
    raise (Parse_error error_message)
  |(Failure "nth") ->
    let error_message = generate_error_message "Not enough parameters provided for option" line_number in
    raise (Parse_error error_message) 

let read_subnet_start tokens declarations line_number=
  try
    let subnet = Ipaddr.V4.of_string_exn(List.hd tokens) in
    match (List.nth tokens 1),(List.nth tokens 3) with
    |"netmask","{" -> (*correct netmask declaration, keep parsing*)
      (let netmask = Ipaddr.V4.of_string_exn (List.nth tokens 2) in
      let parameters,remaining_declarations = read_subnet declarations in
      (*check that scope is defined*)
      match !(parameters.scope_bottom) with
        |None->
          let error_message = Printf.sprintf "The subnet %s does not have a defined range" (List.hd tokens) in
          raise (Parse_error error_message)
        |Some x->  (subnet,netmask,parameters),remaining_declarations)
    |"netmask",_ -> raise (Parse_error "'{' expected after subnet declaration")
    |_,_ -> raise (Parse_error "netmask not declared in subnet declaration")
  with
  |(Ipaddr.Parse_error (x,_)) ->
    let error_message = generate_error_message ("Invalid subnet mask or netmask"^x) line_number in
    raise (Parse_error error_message)
  |(Failure x) -> match x with
    |"hd"-> let error_message = generate_error_message "Error: no subnet mask provided" line_number in
      raise (Parse_error error_message)
    |"nth"-> let error_message = generate_error_message "Error: line formatting incorrect, ensure subnet mask and netmask are both labelled and provided, and finish with {" line_number in
      raise (Parse_error error_message)
    |x -> let error_message = generate_error_message ("Error "^x) line_number in
      raise (Parse_error error_message)

let rec read_host declarations = 
  match declarations with
  |[]->
    let error_message = "Final host declaration incomplete, } expected" in
    raise (Parse_error error_message)
  |(dec,line_number)::tail ->
    try
      let first_token = List.hd dec in
      match first_token with
      |"}"-> {hardware_address= ref None;ip_address= ref None;host_parameters= ref []} (*end of host declaration*)
      |"hardware" ->
        (let hardware_type = List.nth dec 1 in
          match hardware_type with
          |"ethernet"->
            let mac_address = List.nth dec 2 in
            let host_parameters = read_host tail in
            host_parameters.hardware_address := Some mac_address;
            host_parameters
          |x ->
            let error_message = generate_error_message (Printf.sprintf "Unsupported hardware type %s, use ethernet" x) line_number in
            raise (Parse_error error_message)          
        )
      |"fixed-address" ->
        let value = List.nth dec 1 in
        let ip_address = Ipaddr.V4.of_string_exn value in
        let host_parameters = read_host tail in
        host_parameters.ip_address := Some ip_address;
        host_parameters
      |"option" ->
        let new_option = read_option (List.tl dec) line_number in
        let host_parameters = read_host tail in
        host_parameters.host_parameters := new_option::!(host_parameters.host_parameters);
        host_parameters
      | x ->
        let error_message = generate_error_message ("Unknown host parameter "^x) line_number in
        raise (Parse_error error_message)
    with
    |(Ipaddr.Parse_error (x,_)) ->
      let error_message = generate_error_message (Printf.sprintf "Invalid ip address: %s" (List.nth dec 1)) line_number in
      raise (Parse_error error_message)
    |(Failure "nth") ->
      let error_message = generate_error_message "Not enoug arguments for parameter" line_number in
      raise (Parse_error error_message)
          
let read_host_start tokens declarations line_number = 
  try
    let domain_name name = List.hd tokens in
    match (List.nth tokens 1) with
    |"{" ->
      let host_parameters = read_host declarations in
      domain_name,host_parameters
    |_ ->
      let error_message = generate_error_message "Parsing error: '{' expected" line_number in
      raise (Parse_error error_message)
  with
  |(Failure "hd") ->
    let error_message = generate_error_message "No hostname provided" line_number in
    raise (Parse_error error_message)
  |(Failure "nth") ->
    let error_message = generate_error_message "Parsing error: '}' expected" line_number in
    raise (Parse_error error_message)
  |(Failure x) ->
    let error_message = generate_error_message ("Error "^x) line_number in
    raise (Parse_error error_message)
     
(*let read_group input_channel line_number = 
  let line = read_and_format input_channel in
  match line with
  |None -> read_group input_channel (line_number+1)
  |Some line -> *)

let rec read_globals declarations =
  match declarations with
  |[] -> {globals = {default_lease_length=ref None;max_lease_length = ref None;scope_bottom = ref None;scope_top = ref None;parameters = ref []};subnets=ref[]}
  |(dec,line_number)::tail -> 
    let first_token = List.hd dec in
    let rest_of_dec = List.tl dec in
    match first_token with
    |"subnet" ->
      let (new_subnet:Ipaddr.V4.t*Ipaddr.V4.t*working_parameters),(remaining_declarations: ((string list) * int) list) = read_subnet_start rest_of_dec tail line_number in
      let current_options = read_globals remaining_declarations in
      current_options.subnets := new_subnet::(!(current_options.subnets));
      current_options
      (*|"group" -> read_group_start (List.tl tokens) global_parameters*)
      |"option" ->
        let new_option = read_option rest_of_dec line_number in
        let current_options = read_globals tail in
        current_options.globals.parameters := new_option::(!(current_options.globals.parameters));
        current_options
      |"range" ->
        (try
          let scope_bottom = Ipaddr.V4.of_string (List.nth rest_of_dec 0) in
          let scope_top = Ipaddr.V4.of_string (List.nth rest_of_dec 1) in
          let current_options = read_globals tail in
          current_options.globals.scope_bottom := scope_bottom;
          current_options.globals.scope_top := scope_top;
          current_options
        with
        |Failure "nth" ->
          let error_message = generate_error_message "Insufficient arguments for global scope" line_number in
          raise (Parse_error error_message))
      |"default-lease-time" ->
        (try
          let value = List.hd rest_of_dec in
          let lease_length = Some (Int32.of_string value) in
          let current_options = read_globals tail in
           current_options.globals.default_lease_length := lease_length;
           current_options
        with
        |(Failure x) -> match x with
          |"hd" ->
            let error_message = generate_error_message "No argument for default lease length" line_number in
            raise (Parse_error error_message)
          |"int_of_string" ->
            let error_message = generate_error_message "Invalid argument for default lease length" line_number in
            raise (Parse_error error_message)
          |x->
            let error_message = generate_error_message ("Parsing error:"^x) line_number in
            raise (Parse_error error_message)
        )
      |"max-lease-time" ->
       (try
        let value = List.hd rest_of_dec in
          let lease_length = Some (Int32.of_string value) in
          let current_options = read_globals tail in
          current_options.globals.max_lease_length := lease_length;
          current_options
        with
        |(Failure x) -> match x with
          |"hd" ->
            let error_message = generate_error_message "No argument for max lease length" line_number in
            raise (Parse_error error_message)
          |"int_of_string" ->
            let error_message = generate_error_message "Invalid argument for max lease length" line_number in
            raise (Parse_error error_message)
          |x->
            let error_message = generate_error_message ("Parsing error:"^x) line_number in
            raise (Parse_error error_message)
        )
      |_-> let error_message = generate_error_message "Unknown global parameter" line_number in
        raise (Parse_error error_message)

let cut_at_char string char =
  let semicolon_position = Core.Std.String.index string char in
  match semicolon_position with
  |Some x-> String.sub string 0 x
  |None -> string

let remove_comments string = cut_at_char string '#';;

let read_and_format input_channel =
  try
    let next_line = input_line input_channel in
    let no_comments_line = remove_comments next_line in
    let trimmed_line = String.trim (no_comments_line) in
    let declarations = Str.split (Str.regexp ";") trimmed_line in
    let separator = Str.regexp "\( \|\t\)+" in
    let tokens = List.map (Str.split separator) declarations in
    Some tokens
  with
  |End_of_file -> None

let lexing input_channel =
  let rec line_parser input_channel line_number = (*build a list, where each element is all the declarations found on a single line of the config file*)
    let tokens = read_and_format input_channel in
    match tokens with
    |None -> []
    |Some l ->
      let add_line_number n x = x,n in
      let formatted_declarations = List.map (add_line_number line_number) l in
      formatted_declarations :: (line_parser input_channel (line_number+1));
  in
  let lines = line_parser input_channel 1 in
  List.concat lines;; (*now have a list of declarations, labelled with their original line number*)
   
let read_DHCP_config =
  let input_channel = open_in "/etc/dhcpd.conf" in
  let declarations = lexing input_channel in
  read_globals declarations