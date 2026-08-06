# MQTT Option gid-sid map

## GID

### 8000

Default Trout GID

## SID 1110-1150

### 1110
#### What
Indicates the connect message has the magic string and version, but the
content of the message didn't follow the spec for the given version
#### Why
Ill formed messages can be intentionally created to exploit errors in
the system or be a sign of an error in the sender code

### 1111
#### What
Indicates a message was longer than the defined data
#### Why
A message that have spare bytes, not defined to contain data could be
trying to hide a data transfer
