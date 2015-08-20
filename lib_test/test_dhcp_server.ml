(*Tests for DHCP server*)

open OUnit;;
open Lwt.Infix;;
open Dhcpv4_util;;
open Dhcpv4_option;;
open Dhcpv4_option.Packet;;
open Common;;
open Vnetif_common;;
open Console;;

let client_mac_address = "10:9a:dd:c0:ff:ee";;
let client_ip_address = Ipaddr.V4.of_string_exn "192.1.1.10";; (*Used in renewals, rebindings and init-reboot tests*)
let server_ip_address = Ipaddr.V4.of_string_exn "192.1.1.1";; (*Ensure config file agrees*)
let gateway_ip_address1 = Ipaddr.V4.of_string_exn "192.1.2.1";;
let gateway_ip_address2 = Ipaddr.V4.of_string_exn "192.1.3.1";;
let unspecified = Ipaddr.V4.unspecified;;
let unspecifiedint32 = Int32.of_int 0;;


module C = Console
module Cl = Clock
module H = Dhcp_serverv4.Helper(C)(Cl)
open H;;

let t =
 let serverIPs = [server_ip_address] in
 let subnets,global_parameters = H.read_config serverIPs "/etc/Dhcpd.conf" in
 let server_subnet = List.hd(subnets) in
 {server_subnet;serverIPs;subnets;global_parameters};;

let dhcp_packet_builder xid flags ciaddr yiaddr siaddr giaddr options= 
 let open Dhcp_clientv4 in
 let options = Dhcpv4_option.Packet.to_bytes options in
 let options_len = Bytes.length options in
 let buf = Io_page.(to_cstruct (get 1)) in
 set_dhcp_op buf 1; (*client messages always have op = 1*)
 set_dhcp_htype buf 1;
 set_dhcp_hlen buf 6; (*hardware type defaulted to ethernet*)
 set_dhcp_hops buf 0;
 set_dhcp_xid buf xid;
 set_dhcp_flags buf flags;
 set_dhcp_ciaddr buf (Ipaddr.V4.to_int32 ciaddr);
 set_dhcp_yiaddr buf (Ipaddr.V4.to_int32 yiaddr);
 set_dhcp_siaddr buf (Ipaddr.V4.to_int32 siaddr);
 set_dhcp_giaddr buf (Ipaddr.V4.to_int32 giaddr);
 set_dhcp_chaddr client_mac_address 0 buf;
 set_dhcp_sname (Bytes.make 64 '\000') 0 buf;
 set_dhcp_file (Bytes.make 128 '\000') 0 buf;
 set_dhcp_cookie buf 0x63825363l;
 Cstruct.blit_from_string options 0 buf sizeof_dhcp options_len;
 Cstruct.set_len buf (sizeof_dhcp + options_len);;

let options op = {op=`Discover;opts=[]} (*Test options fully separately*)

let test_case ~xid ~flags ~ciaddr ~yiaddr ~siaddr ~giaddr ~options ~dest ~response_expected ~options_test ~expected_yiaddr =
  let raw_packet = dhcp_packet_builder xid flags ciaddr yiaddr siaddr giaddr options in
  let packet = dhcp_packet_of_cstruct raw_packet in
  let result = parse_packet t ~src:client_ip_address ~dst:dest ~packet:packet in (*the server's response to the packet*)
  match result,response_expected with
  |None,false -> () (*No packet expected, none received: job done*)
  |None,true -> assert_failure "Response expected, none received"
  |Some _,false -> assert_failure "No response expected, response received"
  |Some (p,dst),true ->
    let open Dhcp_clientv4 in
    (*assert_failure (Printf.sprintf "yiaddr = %s" (Ipaddr.V4.to_string (Ipaddr.V4.of_int32(get_dhcp_yiaddr p))));*)
    assert_equal 2 (get_dhcp_op p); (*Server messages always have op type 2*)
    assert_equal 1 (get_dhcp_htype p);
    assert_equal 6 (get_dhcp_hlen p);
    assert_equal 0 (get_dhcp_hops p);
    assert_equal xid (get_dhcp_xid p);
    assert_equal 0 (get_dhcp_secs p);
    assert_equal (Ipaddr.V4.unspecified) (Ipaddr.V4.of_int32(get_dhcp_ciaddr p));
    assert_equal flags (get_dhcp_flags p);
    assert_equal expected_yiaddr (Ipaddr.V4.of_int32(get_dhcp_yiaddr p));
    (*let of_byte x =
      Printf.sprintf "%02x" (Char.code x) in
    let chaddr_to_string x =
      let chaddr_size = (Bytes.length x) in
      let dst_buffer = (Bytes.make (chaddr_size * 2) '\000') in
        for i = 0 to (chaddr_size - 1) do
          let thischar = of_byte x.[i] in
            Bytes.set dst_buffer (i*2) (Bytes.get thischar 0);
            Bytes.set dst_buffer ((i*2)+1) (Bytes.get thischar 1)
          done;
          dst_buffer
    in
    let chaddr = (chaddr_to_string) (copy_dhcp_chaddr p) in
    assert_equal client_mac_address chaddr*)
    assert_equal giaddr (Ipaddr.V4.of_int32(get_dhcp_giaddr p)); (*TODO: test client hardware address, test broadcast vs unicast,siaddr*)
    let server_options1 = Cstruct.(copy p sizeof_dhcp (len p - sizeof_dhcp)) in
    let server_options2 = Dhcpv4_option.Packet.of_bytes server_options1 in
    options_test server_options2;;
(*________________________________________________________________________________________________________*)

(*TEST DHCPDISCOVER RESPONSES*)

(*TODO: Need to test various lease lengths*)
let discover_options = options `Discover;; (*The options sent to the server*)

let offer_options_test options = (*tests for the options received from the server*)
(*In offer messages, expect a server identifier and lease time*)
  assert_equal options.op `Offer;
  match find options (function `Lease_time offered_lease -> Some offered_lease |_ -> None) with
  |None -> assert_failure "No offered lease length"
  |Some _->
    match find options (function `Server_identifier id -> Some id |_ -> None) with
    |None -> assert_failure "No id provided -> fail"
    |Some _-> ();;

let discover_test_case = (*A partially applied version of the testing function for convenience, every test case uses these parameters*)
  test_case ~ciaddr:unspecified ~yiaddr:unspecified ~siaddr:unspecified ~options:discover_options ~dest:Ipaddr.V4.broadcast ~options_test:offer_options_test;;

let discover_on_subnet () =
  let open Int32 in
  discover_test_case ~xid:(of_int 11) ~flags:0 ~giaddr:unspecified ~response_expected:true ~expected_yiaddr:(Ipaddr.V4.of_string_exn "192.1.1.2");
  (*Client on same subnet, correctly configured, unicast reply*)
  discover_test_case ~xid:(of_int 12) ~flags:1 ~giaddr:unspecified ~response_expected:true ~expected_yiaddr:(Ipaddr.V4.of_string_exn "192.1.1.3");
  (*as above, with broadcast reply*)
  Lwt.return_unit;;

let discover_off_subnet () =
  let open Int32 in
  discover_test_case ~xid:(of_int 21) ~flags:0 ~giaddr:gateway_ip_address1 ~response_expected:true ~expected_yiaddr:(Ipaddr.V4.of_string_exn "192.1.2.2");
  (*Client on different subnet, unicast reply*)
  discover_test_case ~xid:(of_int 22) ~flags:1 ~giaddr:gateway_ip_address1 ~response_expected:true ~expected_yiaddr:(Ipaddr.V4.of_string_exn "192.1.2.3");
  (*as above, with broadcast reply*)
  Lwt.return_unit;;
 
let nonsense_discovers() =
  let open Int32 in
  discover_test_case ~xid:(of_int 31) ~flags:0 ~giaddr:(Ipaddr.V4.of_string_exn "1.1.1.1") ~response_expected:false ~expected_yiaddr:unspecified;
  Lwt.return_unit;;
(*__________________________________________________________________________________________________________*)
    
(*TEST DHCPREQUEST RESPONSES*)    

let request_options_without_serverID = {op=`Request;opts=[]};; (*Used in rebinding and renewing*)
let request_options_with_serverID requested_ip = {op=`Request;opts=[`Server_identifier server_ip_address;`Requested_ip requested_ip]};; (*Used in all other (valid) requests*)
let request_options_with_requested_address address = {op=`Request;opts=[`Requested_ip address]};; (*Used in init_reboot*)

(*The previous test will have lodged 4 requests with the server, these tests use those 4 requests*)

let ack_options_test options =
(*In ack messages, expect a server identifier and lease time*)
  let open Dhcpv4_option.Packet in
  assert_equal options.op `Ack;
  match find options (function `Lease_time offered_lease -> Some offered_lease |_ -> None) with
  |None -> assert_failure "No offered lease length -> fail"
  |Some _->
    match find options (function `Server_identifier id -> Some id |_ -> None) with
    |None -> assert_failure "No server id provided -> fail"
    |Some _-> ();;

let nak_options_test options =
  assert_equal options.op `Nak;;

let response_test_case requested_ip = (*this is for responding to offers*)
  test_case ~ciaddr:unspecified ~yiaddr:unspecified ~siaddr:unspecified ~options:(request_options_with_serverID requested_ip) ~dest:Ipaddr.V4.broadcast ~options_test:ack_options_test;;

let request_correct () =
  let unitise x = () in
  let open Int32 in
  let raw_packet = dhcp_packet_builder (of_int 41) 0 unspecified unspecified unspecified gateway_ip_address2 discover_options in (*send a discover to the server for use in this test*)
  let packet = dhcp_packet_of_cstruct raw_packet in
  unitise (parse_packet t ~src:client_ip_address ~dst:server_ip_address ~packet:packet);
  (response_test_case (Ipaddr.V4.of_string_exn "192.1.3.2")) ~xid:(of_int 41) ~flags:0 ~giaddr:gateway_ip_address2 ~response_expected:true
    ~expected_yiaddr:(Ipaddr.V4.of_string_exn "192.1.3.2");
  (response_test_case unspecified) ~xid:(of_int 41) ~flags:0 ~giaddr:gateway_ip_address2 ~response_expected:false ~expected_yiaddr:(unspecified);
  (*only the last one should receive a response, since when each discover will override the last one*)
  Lwt.return_unit;;

let request_incorrect () =
  let unitise x = () in
  let open Int32 in
  let raw_packet1 = dhcp_packet_builder (of_int 51) 0 unspecified unspecified unspecified gateway_ip_address2 discover_options in
  let packet1 = dhcp_packet_of_cstruct raw_packet1 in
  unitise (parse_packet t ~src:client_ip_address ~dst:server_ip_address ~packet:packet1);
  let raw_packet2 = dhcp_packet_builder (of_int 52) 0 unspecified unspecified unspecified gateway_ip_address2 discover_options in
  let packet2 = dhcp_packet_of_cstruct raw_packet2 in
  unitise (parse_packet t ~src:client_ip_address ~dst:server_ip_address ~packet:packet2);
  (response_test_case unspecified) ~xid:(of_int 51) ~flags:0 ~giaddr:gateway_ip_address2 ~response_expected:false ~expected_yiaddr:unspecified;
  Lwt.return_unit;;

let requested_ip_address1 = Ipaddr.V4.of_string_exn "192.1.1.10";; (*this should be available*)
let requested_ip_address2 = Ipaddr.V4.of_string_exn "192.1.2.5";; (*wrong subnet*)
let requested_ip_address3 = Ipaddr.V4.of_string_exn "192.1.3.8";;
let requested_ip_address4 = Ipaddr.V4.of_string_exn "192.1.3.9";;

let other_requests_test_case =
 test_case ~yiaddr:unspecified ~siaddr:unspecified ~flags:0;;

let correct_init_reboot () =
  let open Int32 in
  other_requests_test_case ~xid:(of_int 61) ~ciaddr:unspecified ~giaddr:unspecified ~options:(request_options_with_requested_address requested_ip_address1) ~response_expected:true
  ~expected_yiaddr:requested_ip_address1 ~dest:Ipaddr.V4.broadcast ~options_test:ack_options_test; (*legitimate reboot attempt*)
  other_requests_test_case ~xid:(of_int 62) ~ciaddr:unspecified ~giaddr:unspecified ~options:(request_options_with_requested_address requested_ip_address1) ~response_expected:true
  ~expected_yiaddr:unspecified ~dest:Ipaddr.V4.broadcast ~options_test:nak_options_test; (*address should be reserved due to previous test-expect a nak*)
  Lwt.return_unit;;

let incorrect_init_reboot () =
  let open Int32 in
  other_requests_test_case ~xid:(of_int 71) ~ciaddr:unspecified ~giaddr:unspecified ~options:(request_options_with_requested_address requested_ip_address2) ~response_expected:true
  ~expected_yiaddr:unspecified ~dest:Ipaddr.V4.broadcast ~options_test:nak_options_test; (*wrong subnet:nak*)
  other_requests_test_case ~xid:(of_int 72) ~ciaddr:unspecified ~giaddr:unspecified ~options:(request_options_without_serverID) ~response_expected:false ~expected_yiaddr:unspecified
  ~dest:Ipaddr.V4.broadcast ~options_test: nak_options_test;
  (*no requested address, should fail*)
  Lwt.return_unit;;

let renewal_test () = 
  let open Int32 in
  other_requests_test_case ~xid:(of_int 81) ~ciaddr:requested_ip_address3 ~giaddr:gateway_ip_address2 ~options:(request_options_without_serverID) ~response_expected:true ~expected_yiaddr:requested_ip_address3 ~dest:server_ip_address ~options_test:ack_options_test; (*this should work*)
  other_requests_test_case ~xid:(of_int 82) ~ciaddr:requested_ip_address4 ~giaddr:gateway_ip_address1 ~options:(request_options_without_serverID) ~response_expected:true ~expected_yiaddr:requested_ip_address4 ~dest:server_ip_address ~options_test:ack_options_test;
  Lwt.return_unit;;

let suite = 
  ["DHCP discovers on subnet are acknowledged correctly",`Quick,discover_on_subnet;
  "DHCP discovers off subnet are acknowledged correctly",`Quick,discover_off_subnet;
  "DHCP nonsense discovers are ignored",`Quick,nonsense_discovers;
  "Valid offers are completed correctly",`Quick,request_correct;
  "Requests for outdated offers are ignored",`Quick,request_incorrect;
  "Valid Init reboot handled correctly",`Quick,correct_init_reboot;
  "Invalid Init reboot is Nak'd",`Quick,incorrect_init_reboot;
  "Renewals are handled correctly",`Quick,renewal_test;
  ];;