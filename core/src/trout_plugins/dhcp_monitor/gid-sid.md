# DHCP Monitor gid-sid map

## GID

### 8000

Default Trout GID

## SID 1000-1009

### 1001
#### What
Indicates both source and destination IP address was seen outside of the expected range of network addresses of vlan
#### Why
When a packet is seen on a vlan, but with neither the source nor the destination address being from the vlan it is worth investigating

### 1002
#### What
Indicates an IP address was assigned in an DHCP ACK, but from a different range than the last IP address assigned on the given vlan
#### Why
It is common for all addresses on a given vlan to be assigned from the same range, if they aren't we should investigate why

### 1003
#### What
Indicates a packet on a vlan we haven't seen any DHCP address asignments from (meaning we can't evaluate the validity of the IP's used)
#### Why
This is a warning that we are seeing packets on a vlan that we don't have any information about - i.e. we can not evaluate the validity of the addresses used

### 1004-1009

Reserved