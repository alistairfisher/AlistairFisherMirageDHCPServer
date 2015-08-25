type reserved_address = { (*An address that has been offered to a client, but not yet accepted*)
  reserved_ip_address: Ipaddr.V4.t;
  xid: Cstruct.uint32;
  reservation_timestamp: float;
}
  
type lease = {
  lease_length:int32;
  lease_timestamp:float;
  ip_address: Ipaddr.V4.t;
}
  
(*TODO: use client ID to differentiate explicit ID from hardware address, allowing different hardware types.*)  
  
type client_identifier = string;; (*According to RFC 2131, this should be the client's hardware address unless an explicit identifier is provided. The RFC states that the ID must be unique
  within the subnet, but the onus is on the client to ensure this if it chooses to use an explicit identifier: the server shouldn't need to check it for uniqueness. The
  full identifier is the combination of subnet and identifier, but the subnet is implicit in this implementation*)

type subnet = {
  subnet: Ipaddr.V4.t;
  netmask: Ipaddr.V4.t;
  parameters: Dhcpv4_option.t list;
  scope_bottom: Ipaddr.V4.t;
  scope_top: Ipaddr.V4.t;
  max_lease_length: int32;
  default_lease_length: int32;
  serverIP: Ipaddr.V4.t; (*The IP address of the interface that should be used to communicate with hosts on this subnet*)
  static_hosts: (string*Ipaddr.V4.t) list
}