# DHCP Option gid-sid map

## GID

### 8000

Default Trout GID

## SID 1010-1019

### 1010
#### What
Indicates a valid formated DHCP package was found
NOTE: The algorithm focuses on the format of the package, not the content
#### Why
Makes it possible to create rules based on found DHCP packages

### 1011
#### What
Indicates that some passing error happend, i.e. package wasn't formated as a valid dhcp package
NOTE: The algorithm focuses on the format of the package, not the content
#### Why
Enables rules to trigger if something that isn't valid DHCP packages are transmitted

### 1012
#### What
Indicates that a DHCP package doesn't have any option fields
#### Why
Lack of an options field is unexpected formatting of a DHCP message

### 1013
#### What
Package didn't contain the opcode for BOOTREQUEST (1) or BOOTREPLY (2) as specfied by RFC2131
#### Why
If anything other than a valid opcode is used something is wrong

### 1014
#### What
sname field in the header was not zero terminated
#### Why
A string which should be zero terminated but isn't could result in buffer overruns

### 1015
#### What
file field in the header was not zero terminated
#### Why
A string which should be zero terminated but isn't could result in buffer overruns

### 1016-1019

Reserved
