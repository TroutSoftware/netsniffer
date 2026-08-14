# MQTT Option gid-sid map

## GID

### 8000

Default Trout GID

## SID 1110-1150

### 1110
#### What
Indicates the connect message has the magic string and version, but the
content of the message didn't follow the spec for the given version.

If the error is fatal, e.g. prevents futher decoding, decoding will be
abandoned for the current message, and this is the only indication
available for the rule engine.
#### Why
Ill formed messages can be intentionally created to exploit errors in
the system or be a sign of an error in the sender code

### 1111
#### What
Indicates a message was longer than the defined data
#### Why
A message that have spare bytes, not defined to contain data could be
trying to hide a data transfer

### 1112
#### What
Indicates a connack message contained something that didn't follow the
spec for the given version.

If the error is fatal, e.g. prevents futher decoding, decoding will be
abandoned for the current message, and this is the only indication
available for the rule engine.
#### Why
Ill formed messages can be intentionally created to exploit errors in
the system or be a sign of an error in the sender code

### 1113
#### What
Indicates communication on a flow that should be closed (i.e. at least
one side of the communication has signaled the communication has been
terminated
#### Why
Communication on a flow that has been terminated is illegal behavior

### 1114
#### What
Indicates we have fallen out of sync on the server communication,
messages sent from the server to the client will no longer be parsed
#### Why
Messages from the server can no longer be validated by the rule engine,
this can be because of ill formed communication, or because snort lost
a network package due to overload

### 1115
#### What
Indicates we have fallen out of sync on the client communication,
messages sent from the client to the server will no longer be parsed
#### Why
Messages from the client can no longer be validated by the rule engine,
this can be because of ill formed communication, or because snort lost
a network package due to overload

### 1116
#### What
The topic name in a message wasn't legal (e.g. size 0 or above 32,767)
#### Why
A message with an unsupported length could be an attempt to make a
buffer overflow or crash a server or client

### 1117
#### What
Indicates a publish message contained something that didn't follow the
spec for the given version

If the error is fatal, e.g. prevents futher decoding, decoding will be
abandoned for the current message, and this is the only indication
available for the rule engine.
#### Why
Ill formed messages can be intentionally created to exploit errors in
the system or be a sign of an error in the sender code

### 1118
#### What
Indicates a puback message contained something that didn't follow the
spec for the given version

If the error is fatal, e.g. prevents futher decoding, decoding will be
abandoned for the current message, and this is the only indication
available for the rule engine.
#### Why
Ill formed messages can be intentionally created to exploit errors in
the system or be a sign of an error in the sender code

### 1119
#### What
Indicates a pubrec message contained something that didn't follow the
spec for the given version

If the error is fatal, e.g. prevents futher decoding, decoding will be
abandoned for the current message, and this is the only indication
available for the rule engine.
#### Why
Ill formed messages can be intentionally created to exploit errors in
the system or be a sign of an error in the sender code

### 1120
#### What
Indicates a pubrel message contained something that didn't follow the
spec for the given version

If the error is fatal, e.g. prevents futher decoding, decoding will be
abandoned for the current message, and this is the only indication
available for the rule engine.
#### Why
Ill formed messages can be intentionally created to exploit errors in
the system or be a sign of an error in the sender code

### 1121
#### What
Indicates a pubcomp message contained something that didn't follow the
spec for the given version

If the error is fatal, e.g. prevents futher decoding, decoding will be
abandoned for the current message, and this is the only indication
available for the rule engine.
#### Why
Ill formed messages can be intentionally created to exploit errors in
the system or be a sign of an error in the sender code

### 1122
#### What
Indicates a subscribe message contained something that didn't follow the
spec for the given version

If the error is fatal, e.g. prevents futher decoding, decoding will be
abandoned for the current message, and this is the only indication
available for the rule engine.
#### Why
Ill formed messages can be intentionally created to exploit errors in
the system or be a sign of an error in the sender code

### 1123
#### What
Indicates a suback message contained something that didn't follow the
spec for the given version

If the error is fatal, e.g. prevents futher decoding, decoding will be
abandoned for the current message, and this is the only indication
available for the rule engine.
#### Why
Ill formed messages can be intentionally created to exploit errors in
the system or be a sign of an error in the sender code
