open OUnit;;
open Dhcpv4_option;;

let test_ip1 = Ipaddr.V4.of_string_exn "192.1.1.1";;
let test_ip2 = Ipaddr.V4.of_string_exn "99.120.234.2";;
let test_ip3 = Ipaddr.V4.of_string_exn "0.0.0.0";;
let test_ip4 = Ipaddr.V4.of_string_exn "255.255.255.255";;

let test_option option =
  let initial_list = [option;`End] in
  assert_equal (Unmarshal.of_bytes(Marshal.to_bytes option)) [option];;

let test_pad () = 
  test_option (`Pad);Lwt.return_unit;;

let test_subnet_mask () =
  test_option (`Subnet_mask test_ip1);Lwt.return_unit;;

let test_time_server () =
  test_option (`Time_server [test_ip1;test_ip2]);Lwt.return_unit;;
  
let test_hostname () =
  test_option (`Hostname "Alistairs-computer");Lwt.return_unit;;

let test_root_path () =
  test_option (`Root_path "/home/alistair");Lwt.return_unit;;
  
let test_ip_forwarding () =
  test_option (`Ip_forwarding true);
  test_option (`Ip_forwarding false);Lwt.return_unit;;

let test_arp_timeout () =
  test_option (`Arp_timeout (Int32.of_int 55));Lwt.return_unit;;
  
let test_server_identifier () =
  test_option (`Server_identifier test_ip4);
  Lwt.return_unit;;

let suite =
  ["Pad",`Quick,test_pad;
  "Subnet mask",`Quick,test_subnet_mask]