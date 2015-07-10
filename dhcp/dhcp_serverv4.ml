(*Initial DHCP- lists for storage (need to migrate to IRMIN), no static allocation,no additional information (DHCPInform),can't handle DHCPDecline or Release,
server IP is always this server,no support for requested IP (in options),no address selection based on giaddr,no requested lease support, NO OPTIONS support (including mandatory fields),
no probing before reusing address, *)

open Lwt.Infix;;
open Printf;;

module Make (Console:V1_LWT.CONSOLE)
    (Time:V1_LWT.TIME)
    (Clock:V1.CLOCK)
    (Udp:V1_LWT.UDPV4) = struct

    type reserved_address = {
      ip_address: Ipaddr.V4.t;
      xid: Cstruct.uint32;
      timestamp: float;
    }
    
    type t = { (*not sure if this is appropriate*)
      c: Console.t;
      udp: Udp.t;
      mac: Macaddr.t;
    }
    
    cstruct dhcp {
        uint8_t op;
        uint8_t htype;
        uint8_t hlen;
        uint8_t hops;
        uint32_t xid;
        uint16_t secs;
        uint16_t flags;
        uint32_t ciaddr;
        uint32_t yiaddr;
        uint32_t siaddr;
        uint32_t giaddr;
        uint8_t chaddr[16];
        uint8_t sname[64];
        uint8_t file[128];
        uint32_t cookie
      } as big_endian
    
      cenum mode {
      BootRequest = 1;
      BootReply
    } as uint8_t
    
    let rec list_gen(bottom,top) =(*TODO: need to insert into main dhcp function*)
      let a = Ipaddr.V4.to_int32 bottom in
      let b = Ipaddr.V4.to_int32 top in
      if (a>b) then []
	    else bottom::list_gen(Ipaddr.V4.of_int32(Int32.add a Int32.one),top);;
    
    let output_broadcast t ~xid ~ciaddr ~yiaddr ~siaddr ~giaddr ~secs ~chaddr ~flags ~options =
      let options = Dhcpv4_option.Packet.to_bytes options in
      let options_len = Bytes.length options in
      let total_len = options_len + sizeof_dhcp in
      let buf = Io_page.(to_cstruct (get 1)) in
      set_dhcp_op buf (mode_to_int BootReply);
      set_dhcp_htype buf 1;
      set_dhcp_hlen buf 6;
      set_dhcp_hops buf 0;
      set_dhcp_xid buf xid;
      set_dhcp_secs buf secs;
      set_dhcp_flags buf flags;
      set_dhcp_ciaddr buf 0l;
      set_dhcp_yiaddr buf (Ipaddr.V4.to_int32 yiaddr);
      set_dhcp_siaddr buf (Ipaddr.V4.to_int32 siaddr);
      set_dhcp_giaddr buf (Ipaddr.V4.to_int32 giaddr);
      (* TODO add a pad/fill function in cstruct *)
      let macaddr = Macaddr.to_bytes t.mac in
      set_dhcp_chaddr (macaddr ^ (Bytes.make 10 '\000')) 0 buf;
      set_dhcp_sname (Bytes.make 64 '\000') 0 buf; (*check these 2*)
      set_dhcp_file (Bytes.make 128 '\000') 0 buf;
      set_dhcp_cookie buf 0x63825363l;
      Cstruct.blit_from_string options 0 buf sizeof_dhcp options_len;
      let dest_ip_address = if (flags = 0) then yiaddr
        else Ipaddr.V4.broadcast
      in
      let buf = Cstruct.set_len buf (sizeof_dhcp + options_len) in
      Console.log_s t.c (sprintf "Sending DHCP broadcast (length %d)" total_len)
      >>= fun () ->
      Udp.write ~dest_ip: dest_ip_address ~source_port:67 ~dest_port:68 t.udp buf;;
  
    (*unwrap DHCP packet, case split depending on the contents*)
    let input t ~src ~dst:_ ~srcport:_ ~reserved_addresses ~in_use_addresses ~available_addresses ~serverIP ~leaseLength ~server_parameters buf = (*lots of duplication with client, need to combine into one unit*)
	    let ciaddr = Ipaddr.V4.of_int32 (get_dhcp_ciaddr buf) in
      let yiaddr = Ipaddr.V4.of_int32 (get_dhcp_yiaddr buf) in
	    let siaddr = Ipaddr.V4.of_int32 (get_dhcp_siaddr buf) in
	    let giaddr = Ipaddr.V4.of_int32 (get_dhcp_giaddr buf) in
      let secs = get_dhcp_secs buf in
	    let xid = get_dhcp_xid buf in
	    let of_byte x =
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
      let chaddr = (chaddr_to_string) (copy_dhcp_chaddr buf) in
      let flags = get_dhcp_flags buf in
	    let options = Cstruct.(copy buf sizeof_dhcp (len buf - sizeof_dhcp)) in (*need to look inside the options packet to see if server id is set: this distinguishes a request from a renewal*)
	    let packet = Dhcpv4_option.Packet.of_bytes options in
      Lwt_list.iter_s (Console.log_s t.c)
        [ "DHCP response:";
          sprintf "input ciaddr %s yiaddr %s" (Ipaddr.V4.to_string ciaddr) (Ipaddr.V4.to_string yiaddr);
          sprintf "siaddr %s giaddr %s" (Ipaddr.V4.to_string siaddr) (Ipaddr.V4.to_string giaddr);
          sprintf "chaddr %s sname %s file %s" (chaddr) (copy_dhcp_sname buf) (copy_dhcp_file buf) ]
      >>= fun () ->
      let open Dhcpv4_option.Packet in
      let open Dhcp_serverv4_options in
      let client_identifier = match find packet (function `Client_id id -> Some id |_ -> None) with
        |None -> chaddr
        |Some x-> x
      in
	    match packet.op with
		    |`Discover ->
          let address = List.hd (!available_addresses) in
            reserved_addresses:=(client_identifier,{ip_address=address;xid=xid;timestamp=Clock.time()})::(!reserved_addresses);
			      available_addresses:=List.tl(!available_addresses);
            let options = make_options ~client_requests: (packet.opts) ~serverIP: serverIP ~lease_length:leaseLength ~message_type:`Offer in
            (*send DHCP Offer*)
            output_broadcast t ~xid:xid ~ciaddr:0 ~yiaddr:address ~siaddr:serverIP ~giaddr:giaddr ~secs:secs ~chaddr:chaddr ~flags:flags ~options:options;
		    |`Request -> (*TODO: case split request and renewal/verification (RFC page 30)*)
          (*let server_identifier = find packet (function `Server_identifier id -> id |_ -> Ipaddr.V4.of_string "0.0.0.0")*) in (*TODO: handle case where id is not specified (i.e. error)*)*)
          if (siaddr=serverIP&&List.mem_assoc client_identifier (!reserved_addresses) && ((List.assoc client_identifier (!reserved_addresses)).xid=xid)) then ( (*the client is requesting the IP address, this is not a renewal*)
            let address = (List.assoc client_identifier (!reserved_addresses)).ip_address in
            in_use_addresses:=(client_identifier,{ip_address=address;xid=xid;timestamp=Clock.time()})::!in_use_addresses;
            reserved_addresses:=List.remove_assoc client_identifier (!reserved_addresses);
            let options = make_options ~client_requests: (packet.opts) ~serverIP: serverIP ~lease_length:leaseLength ~message_type:`Ack in
            output_broadcast t ~xid:xid ~ciaddr:ciaddr ~yiaddr:address ~siaddr:serverIP ~giaddr:giaddr ~secs:secs ~chaddr:chaddr ~flags:flags ~options:options;
          )
          else Lwt.return_unit;
          (*TODO: else remove association from reserved, also remember separate 0 case*)
        |`Decline ->
			    if (List.mem_assoc client_identifier (!reserved_addresses)) then
            let address = (List.assoc chaddr (!reserved_addresses)).ip_address in
            in_use_addresses:=("0", {ip_address=address;xid=xid;timestamp=Clock.time()})::!in_use_addresses; (*0 is a placeholder as real hardware address unknown, need some method of avoiding garbage collection, and to notify network admin, change xid*)
            reserved_addresses:=List.tl(!reserved_addresses); Lwt.return_unit;
          else Lwt.return_unit;
        |`Release -> (*this may give errors with duplicate packets, should wipe ALL entries*)
          if (List.mem_assoc client_identifier (!in_use_addresses)) then
            (let address = (List.assoc client_identifier (!in_use_addresses)).ip_address in
            available_addresses:=address::(!available_addresses);
            in_use_addresses:=List.remove_assoc client_identifier (!in_use_addresses));
          Lwt.return_unit;
        |`Inform -> Console.log_s t.c "Inform received"; (*TODO: construct real packet*) 
        | _ ->Lwt.return_unit;; (*this is a packet meant for a client*)
     
    let rec garbage_collect ~reserved_addresses ~in_use_addresses ~leaselength ~collection_interval= (*TODO: accomodate infinite lease*)
      let rec gc l leaselength = match l with
        |[] -> []
        |h::t -> if (Clock.time()-.(snd h).timestamp > leaselength) then gc t leaselength
          else h::gc t leaselength
      in Time.sleep(collection_interval)>>=fun()->(reserved_addresses:=(gc !reserved_addresses leaselength));(in_use_addresses:=(gc !in_use_addresses leaselength));garbage_collect ~reserved_addresses:reserved_addresses ~in_use_addresses:in_use_addresses ~leaselength:leaselength ~collection_interval:collection_interval;;
        
    (*let dhcp ~scopebottom ~scopetop ~leaselength ~serverIP ~udp ~probe:true ~subnetmask:NONE ~DNSservers:NONE ~ ~= (*note: lease time is in seconds. 0xffffffff is reserved for infinity*)
      let reserved_addresses:(string*reserved_address) list ref = ref [] in (*clientID,xid,IPaddress,timestamp*)
      let in_use_addresses:(string*reserved_address) list ref = ref [] in
    	let available_addresses = ref listgen(scopebottom,scopetop) in*)
end