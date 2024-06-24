# DHCP Option gid-sid map

## GID

### 8000

Default Trout GID

## SID 1010-1030

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
#### NOTE
This will also generate 1011 parsing error

### 1014
#### What
sname field in the header was not zero terminated
#### Why
A string which should be zero terminated but isn't could result in buffer overruns
#### NOTE
This will also generate 1011 parsing error


### 1015
#### What
file field in the header was not zero terminated
#### Why
A string which should be zero terminated but isn't could result in buffer overruns
#### NOTE
This will also generate 1011 parsing error


### 1016
#### What
There should be a magic number at the beginning of the DHCP options fields, if that number isn't found this even will be raised
#### Why
A package with a wrong magic number is either not a DHCP package or a corrupted one, in either case it shouldn't be interpreted as a valid one
#### NOTE
This will also generate 1011 parsing error


### 1017
#### What
Options part of DHCP packet was corrupted in some way
#### Why
A corrupted DHCP packet should never appear on the netwrok
#### NOTE
This will also generate 1011 parsing error

### 1018
#### What
We have a DHCP packet that is not detected as a flow by snort, something spooky is going on
#### Why
If this happens, something we don't understand is happening, and we can't evaluate on the content of the package in rules, as this is depending on the flow data
#### NOTE
This will also generate 1011 parsing error

### 1019-1030

Reserved
