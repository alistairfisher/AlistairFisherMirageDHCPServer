open OUnit;;
open Dhcpv4_option;;

let test_ip1 = Ipaddr.V4.of_string_exn "192.1.1.1";;
let test_ip2 = Ipaddr.V4.of_string_exn "99.120.234.2";;
let test_ip3 = Ipaddr.V4.of_string_exn "0.0.0.0";;
let test_ip4 = Ipaddr.V4.of_string_exn "255.255.255.255";;

let test_option option =
  let initial_list = [option;`End] in
  let marshalled_list = List.map (Marshal.to_bytes) initial_list in
  let bytes = Bytes.concat Bytes.empty marshalled_list in
  Printf.printf "%s" (t_to_string (List.hd (Unmarshal.of_bytes(bytes))));
  assert_equal (Unmarshal.of_bytes(bytes)) [option];;

let test_subnet_mask () =
  test_option (`Subnet_mask test_ip1);Lwt.return_unit;;

let test_time_server () =
  test_option (`Time_server [test_ip1;test_ip2]);Lwt.return_unit;;

let test_policy_filter () =
  test_option (`Policy_filter [test_ip1,test_ip2;test_ip3,test_ip4]);Lwt.return_unit;;
 
let test_hostname () =
  test_option (`Hostname "Alistairs-computer");Lwt.return_unit;;

let test_root_path () =
  test_option (`Root_path "/home/alistair");Lwt.return_unit;;
  
let test_ip_forwarding () =
  test_option (`Ip_forwarding true);
  test_option (`Ip_forwarding false);Lwt.return_unit;;

let test_arp_timeout () =
  test_option (`Arp_timeout (Int32.of_int 55));Lwt.return_unit;;

let test_client_identifier () =
  test_option (`Client_identifier "Host1");Lwt.return_unit;;
  
let test_server_identifier () =
  test_option (`Server_identifier test_ip4);
  Lwt.return_unit;;
  
let test_plateau_table () =
  test_option (`Mtu_plateau [1;2;3]);Lwt.return_unit;;

let test_default_ip_ttl () =
  test_option (`Default_ip_ttl 5);Lwt.return_unit;;

let test_interface_mtu () =
  test_option (`Mtu_interface 230);Lwt.return_unit;;

let suite =
  ["Subnet mask",`Quick,test_subnet_mask;
  "Time server",`Quick,test_time_server;
  "Test hostname",`Quick,test_hostname;
  "Test root path",`Quick,test_root_path;
  "Test ip forwarding",`Quick,test_ip_forwarding;
  "Test arp timeout",`Quick,test_arp_timeout;
  "Test server identifier",`Quick,test_server_identifier;
  "Test client identifier",`Quick,test_client_identifier;
  "Test policy filter",`Quick,test_policy_filter;
  "Test plateau table",`Quick,test_plateau_table;
  "Test default ip ttl",`Quick,test_default_ip_ttl;
  "Test interface mtu",`Quick,test_interface_mtu]