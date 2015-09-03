(*Tests for DHCP server*)

open OUnit;;
open Lwt.Infix;;
open Dhcpv4_util;;
open Dhcpv4_option;;
open Dhcpv4_option.Packet;;
open Common;;
open Vnetif_common;;
open Console;;

  module C = Console_unix
  module Cl = Clock
  module I = Irmin_mem.Make
  module H = Dhcp_serverv4.Internal(C)(Cl)(I)
  open H;;

  let irmin_config = Irmin_mem.config();;

  let client_mac_address = "10:9a:dd:c0:ff:ee";;
  let client_ip_address = Ipaddr.V4.of_string_exn "192.1.1.10";; (*Used in renewals, rebindings and init-reboot tests*)
  let server_ip_address = Ipaddr.V4.of_string_exn "192.1.1.1";; (*Ensure config file agrees*)
  let gateway_ip_address1 = Ipaddr.V4.of_string_exn "192.1.2.1";;
  let gateway_ip_address2 = Ipaddr.V4.of_string_exn "192.1.3.1";;
  
  let make_subnet scope_bottom scope_top reserved_hosts =
    let open Data_structures in
    let f (a,b) = a,(Ipaddr.V4.of_string_exn b) in
    let reserved_hosts = List.map f reserved_hosts in
    let scope_bottom = Ipaddr.V4.of_string_exn scope_bottom in
    let scope_top = Ipaddr.V4.of_string_exn scope_top in
    {
      subnet = scope_bottom;
      netmask = Ipaddr.V4.of_string_exn "255.255.255.0";
      parameters = [];
      scope_bottom = scope_bottom;
      scope_top = scope_top;
      max_lease_length = Int32.of_int 60;
      default_lease_length = Int32.of_int 30;
      serverIP = server_ip_address;
      static_hosts = reserved_hosts;
    };;

  let make_t =
    let reserved_hosts1 = ["host1","192.1.1.11"] in
    Console_unix.connect "console" >>=  fun c ->
    match c with
    |`Error _ -> raise (Failure "broken console")
    |`Ok console ->
    I.create irmin_config (task "/Test") >>= fun addresses ->
    (I.update (addresses "initialise store") ["/Test"] Table.empty) >>= fun () ->
    Lwt.return
      {
        c=console;
        server_subnet = (make_subnet "192.1.1.2" "192.1.1.10" reserved_hosts1);
        serverIPs = [Ipaddr.V4.of_string_exn "192.1.1.1"];
        subnets =
          [make_subnet "192.1.1.2" "192.1.1.10" reserved_hosts1;
          make_subnet "192.1.2.2" "192.1.2.10" [];
          make_subnet "192.1.3.2" "192.1.3.10" []];
        global_parameters = [];
        addresses;
        irmin_config;
        node = Table.Path.create ["/Test"];
      };;

  let unspecified = Ipaddr.V4.unspecified;;
  let unspecifiedint32 = Int32.of_int 0;;

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

  let test_case ~xid ~flags ~ciaddr ~yiaddr ~siaddr ~giaddr ~options ~dest ~response_expected ~options_test ~expected_yiaddr =
    let raw_packet = dhcp_packet_builder xid flags ciaddr yiaddr siaddr giaddr options in (*This is a cstruct*)
    let packet = dhcp_packet_of_cstruct raw_packet in
    make_t >>= fun t->
    parse_packet t ~src:client_ip_address ~dst:dest ~packet:packet >>= fun result -> (*the server's response to the packet*)
    match result,response_expected with
    |None,false -> Lwt.return_unit (*No packet expected, none received: job done*)
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
      options_test server_options2;
      Lwt.return_unit;;
  (*________________________________________________________________________________________________________*)

  (*TEST DHCPDISCOVER RESPONSES*)

  (*TODO: Need to test various lease lengths*)
  let discover_options = {op=`Discover;opts=[]};; (*The options sent to the server*)

  let offer_options_test options = (*tests for the options received from the server*)
  (*In offer messages, expect a server identifier and lease time*)
    assert_equal options.op `Offer;
    match find options (function `Requested_lease offered_lease -> Some offered_lease |_ -> None) with
    |None -> assert_failure "No offered lease length"
    |Some _->
      match find options (function `Server_identifier id -> Some id |_ -> None) with
      |None -> assert_failure "No id provided -> fail"
      |Some _-> ();;

  let discover_test_case = (*A partially applied version of the testing function for convenience, every test case uses these parameters*)
    test_case ~ciaddr:unspecified ~yiaddr:unspecified ~siaddr:unspecified ~dest:Ipaddr.V4.broadcast ~options_test:offer_options_test;;

  let discover_on_subnet () =
    let open Int32 in
    discover_test_case ~xid:(of_int 11) ~flags:0 ~giaddr:unspecified ~response_expected:true ~expected_yiaddr:(Ipaddr.V4.of_string_exn "192.1.1.2") ~options:discover_options
    >>= fun ()->
    (*Client on same subnet, correctly configured, unicast reply, should receive first ip address in scope as yiaddr*)
    discover_test_case ~xid:(of_int 12) ~flags:1 ~giaddr:unspecified ~response_expected:true ~expected_yiaddr:(Ipaddr.V4.of_string_exn "192.1.1.3") ~options:discover_options
    (*as above, with broadcast reply, should take second address in range*)


  let discover_off_subnet () =
    let open Int32 in
    discover_test_case ~xid:(of_int 21) ~flags:0 ~giaddr:gateway_ip_address1 ~response_expected:true ~expected_yiaddr:(Ipaddr.V4.of_string_exn "192.1.2.2") ~options:discover_options
    >>= fun () ->
    (*Client on different subnet, unicast reply*)
    discover_test_case ~xid:(of_int 22) ~flags:1 ~giaddr:gateway_ip_address1 ~response_expected:true ~expected_yiaddr:(Ipaddr.V4.of_string_exn "192.1.2.3") ~options:discover_options
    (*as above, with broadcast reply*)
 
  let nonsense_discovers() =
    let open Int32 in
    discover_test_case ~xid:(of_int 31) ~flags:0 ~giaddr:(Ipaddr.V4.of_string_exn "1.1.1.1") ~response_expected:false ~expected_yiaddr:unspecified  ~options:discover_options

  let add_client_id id options =
    let opts = options.opts in
    let new_opts = [`Client_identifier id;`End] @opts in
    {op = options.op;opts=new_opts};;

  let static_host_test () =
    let open Int32 in
    discover_test_case ~xid:(of_int 91) ~flags:0 ~giaddr: unspecified ~response_expected:true ~expected_yiaddr:(Ipaddr.V4.of_string_exn "192.1.1.11")
      ~options:(add_client_id "" discover_options)
  (*__________________________________________________________________________________________________________*)
    
  (*TEST DHCPREQUEST RESPONSES*)    

  let request_options_without_serverID = {op=`Request;opts=[]};; (*Used in rebinding and renewing*)
  let request_options_with_serverID requested_ip = {op=`Request;opts=[`Server_identifier server_ip_address;`Requested_ip_address requested_ip]};; (*Used in all other (valid) requests*)
  let request_options_with_requested_address address = {op=`Request;opts=[`Requested_ip_address address]};; (*Used in init_reboot*)

  let ack_options_test options =
  (*In ack messages, expect a server identifier and lease time*)
    let open Dhcpv4_option.Packet in
    assert_equal options.op `Ack;
    match find options (function `Requested_lease offered_lease -> Some offered_lease |_ -> None) with
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
    make_t >>= fun t ->
    unitise (parse_packet t ~src:client_ip_address ~dst:server_ip_address ~packet:packet);
    (response_test_case (Ipaddr.V4.of_string_exn "192.1.3.2")) ~xid:(of_int 41) ~flags:0 ~giaddr:gateway_ip_address2 ~response_expected:true
      ~expected_yiaddr:(Ipaddr.V4.of_string_exn "192.1.3.2") >>= fun t ->
    (response_test_case unspecified) ~xid:(of_int 41) ~flags:0 ~giaddr:gateway_ip_address2 ~response_expected:false ~expected_yiaddr:(unspecified);;
    (*only the first one should receive a response, since the address will be active when the second address goes through*)

  let request_incorrect () = (*TODO: missing test case??*)
    let unitise x = () in
    let open Int32 in
    let raw_packet1 = dhcp_packet_builder (of_int 51) 0 unspecified unspecified unspecified gateway_ip_address2 discover_options in
    let packet1 = dhcp_packet_of_cstruct raw_packet1 in
    make_t >>= fun t ->
    unitise (parse_packet t ~src:client_ip_address ~dst:server_ip_address ~packet:packet1);
    let raw_packet2 = dhcp_packet_builder (of_int 52) 0 unspecified unspecified unspecified gateway_ip_address2 discover_options in
    let packet2 = dhcp_packet_of_cstruct raw_packet2 in
    unitise (parse_packet t ~src:client_ip_address ~dst:server_ip_address ~packet:packet2);
    (response_test_case unspecified) ~xid:(of_int 51) ~flags:0 ~giaddr:gateway_ip_address2 ~response_expected:false ~expected_yiaddr:unspecified;;

  let requested_ip_address1 = Ipaddr.V4.of_string_exn "192.1.1.10";; (*this should be available*)
  let requested_ip_address2 = Ipaddr.V4.of_string_exn "192.1.2.5";; (*wrong subnet*)
  let requested_ip_address3 = Ipaddr.V4.of_string_exn "192.1.3.8";;
  let requested_ip_address4 = Ipaddr.V4.of_string_exn "192.1.3.9";;

  let other_requests_test_case =
   test_case ~yiaddr:unspecified ~siaddr:unspecified ~flags:0;;

  let correct_init_reboot () =
    let open Int32 in
    other_requests_test_case ~xid:(of_int 61) ~ciaddr:unspecified ~giaddr:unspecified ~options:(request_options_with_requested_address requested_ip_address1) ~response_expected:true
    ~expected_yiaddr:requested_ip_address1 ~dest:Ipaddr.V4.broadcast ~options_test:ack_options_test (*legitimate reboot attempt*) >>= fun () ->
    other_requests_test_case ~xid:(of_int 62) ~ciaddr:unspecified ~giaddr:unspecified ~options:(request_options_with_requested_address requested_ip_address1) ~response_expected:true
    ~expected_yiaddr:unspecified ~dest:Ipaddr.V4.broadcast ~options_test:nak_options_test;; (*address should be reserved due to previous test-expect a nak*)

  let incorrect_init_reboot () =
    let open Int32 in
    other_requests_test_case ~xid:(of_int 71) ~ciaddr:unspecified ~giaddr:unspecified ~options:(request_options_with_requested_address requested_ip_address2) ~response_expected:true
    ~expected_yiaddr:unspecified ~dest:Ipaddr.V4.broadcast ~options_test:nak_options_test (*wrong subnet:nak*)
    >>= fun () ->
    other_requests_test_case ~xid:(of_int 72) ~ciaddr:unspecified ~giaddr:unspecified ~options:(request_options_without_serverID) ~response_expected:false ~expected_yiaddr:unspecified
    ~dest:Ipaddr.V4.broadcast ~options_test: nak_options_test
    (*no requested address, should fail*)

  let renewal_test () = 
    let open Int32 in
    other_requests_test_case ~xid:(of_int 81) ~ciaddr:requested_ip_address3 ~giaddr:gateway_ip_address2 ~options:(request_options_without_serverID) ~response_expected:true
      ~expected_yiaddr:requested_ip_address3 ~dest:server_ip_address ~options_test:ack_options_test (*this should work*) >>= fun () ->
    other_requests_test_case ~xid:(of_int 82) ~ciaddr:requested_ip_address4 ~giaddr:gateway_ip_address1 ~options:(request_options_without_serverID) ~response_expected:true
      ~expected_yiaddr:requested_ip_address4 ~dest:server_ip_address ~options_test:ack_options_test;;

  let suite = 
    ["DHCP discovers on subnet are acknowledged correctly",`Quick,discover_on_subnet;
    "DHCP discovers off subnet are acknowledged correctly",`Quick,discover_off_subnet;
    "DHCP nonsense discovers are ignored",`Quick,nonsense_discovers;
    "Static hosts get allocated address",`Quick,static_host_test;
    "Valid offers are completed correctly",`Quick,request_correct;
    "Requests for outdated offers are ignored",`Quick,request_incorrect;
    "Valid Init reboot handled correctly",`Quick,correct_init_reboot;
    "Invalid Init reboot is Nak'd",`Quick,incorrect_init_reboot;
    "Renewals are handled correctly",`Quick,renewal_test;
    ];;