# Overall

The files in this folder defines a series of plugins that can be used
to parse and make rules for mqtt network traffic

The inspector knows about MQTT 3.1, 3.1.1 and 5.0 standards (protocol
versions 3, 4 and 5) other protocol numbers will be rejected, however
it can only interpret messages (beyond the msg type ID) from version 3.1


## Examples of alerts:

      ---
    
      alert mqtt (
        mqtt_field: Subscribe.Topic, !regex ".*factory.*";
        sid: 3100010;
      )
    
      generates an alert on all subscribe messages with topics that doesn't contain the string "factory"
    
      ---
    
      alert mqtt (
        mqtt_field: !Flow.ClientID, regex "chef";
        mqtt_field: Subscribe.Topic, match "kitchen/#";
        sid: 3100011;
      )
    
      generates an alert on all subscribe messages to the kitchen topic tree, as long as the client isn't the chef

      ---
      
      alert mqtt (        
        mqtt_field: Subscribe.Topic, match "kitchen/#", regex "A/\\+/B";
        sid: 3200011;
      )

      generates an alert on subscriptions to topics starting with "kitchen/", "+", "#" or being the exact string A/+/B, note the double escape needed in the regex

      ---
      
      alert mqtt (        
        mqtt_field: Subscribe.Topic, regex "A/C/B|A/B(/.*)?";
        sid: 3100011;
      )

      generates an alert on subscriptions to topics where the subscribe string is "A/B/C" or starts with the path "A/B"
          
      ---
    
      alert mqtt (
        mqtt_field: ConnAck.ReturnCode, range_match "=4";
        sid: 3100012;
      )
    
      generates an alert on all connection attempts where the username/password was rejected by the server

      ---

      alert mqtt (
        msg: "mqtt client id with new ip";

        gid:8000;
        sid:1132;
      )

      generates an alert when a client id is seen on a new up

      ---

      alert mqtt (
        msg: "Disconnect message received";
        mqtt_field: Msg.Disconnect;

        sid: 3100013;
      )

      Alert will fire only if the message is the Disconnect message

## regex matching

A regex match needs to match the complete string being investigated.

e.g.:

regex "B" - will only match the complete string "B", not "ABC"

regex ".*B.*" - will match any string containing a "B" (incl "ABC")

## match topic matching

The match topic matching can only be used on topics, and match under the
MQTT 3.1 topic matching rules - a match will happen if there can be
constructed a topic string that matches both the match argument and the
topic string from the message.

e.g.:

match "A/B/#" - will match topic strings like "A/B", "A/B/C", "A/B/C/D".

                it will also match "#" bc we can construct a string
                "A/B" that satisfies both                
                
                "+/B/+/D" will match bc a string like "A/B/C/D" would
                satisfy both

                but not "/+/#" bc no topic string can be created that
                satisfies both  (one require it starts with a "/" the
                other that it doesn't)
                
### List of regex/match strings

Multiple regex/match checks can be listed in a mqtt_field line, the
rule will match if any of the regex/match conditions listed are
satisfied, e.g.:

mqtt_field: Connect.UserName, regex "alice", regex "bob"

will evaluate to true if the user name is either alice or bob, think of
the list as having implicit "OR" between them.  In the above example
it could also be written as ...regex "alice|bob", but that would not
illustrate the point of the explanation.

To get an "AND" like functionality add multiple mqtt_filed statements to
the rule, e.g.:

mqtt_field: Subscribe.Topic, regex "factory(/.*)?" 
mqtt_field: Subscribe.Topic, regex "location(/.*)?"

will match someone subscribing to both something that starts with
factory and to something starting with location.

If on the other hand matches to someone subscribing with wild cards
would also be accepted it could be written as:

mqtt_field: Subscribe.Topic, match "factory/#" 
mqtt_field: Subscribe.Topic, match "location/#"

to express this with regex would require something like:

mqtt_field: Subscribe.Topic, regex "#|(\\+/?|factory(/.*)?)" 
mqtt_field: Subscribe.Topic, regex "#|(\\+/?|location(/.*)?)"


## List of fields that can be used in mqtt_field rules

The current list of valid fields that can be checked with mqtt_field
rules can be found in the mqtt_field_map defined in
ips_option_mqtt_field.cc the rule will evaluate to true if the field
exists in the current message/packet being evaluated by the rule engine
or if it is part of the connection/flow, e.g. the flow.ClientID
containing the client id of the flow can be accessed in all messages


### Flow specific that are available in all messages after a connect
Flow.ClientID : The client ID (if set in connect)
Flow.ProtocolLevel : The protocol level from the spec
                      (3 = 3.1, 4 = 3.1.1, 5 = 5.0)
                      
### The type of the message

(This will be set even for 3.1.1 and 5.0 connections)

You usually don't need to check the message type if you also check for a
specific field in the message - but for message types that don't have
data like Msg.PingReq, it is an easy way to detect them.

Msg.Type        - Sets cursor at a numeric representation of the type
Msg.Connect     
Msg.ConnAck
Msg.Publish
Msg.PubAck
Msg.PubRec
Msg.PubRel
Msg.PubComp
Msg.Subscribe
Msg.SubAck
Msg.Unsubscribe
Msg.UnsubAck
Msg.PingReq
Msg.PingResp
Msg.Disconnect
Msg.Auth        - Only valid for 5.0

### Common data

Msg.Extra       - Sets the cursor at any data beyond what was expected
                  in the message

### Msg specific fields

The message specific fields will unless they are of a flag (boolean)
type move the cursor to the field.

For the flag/boolean type of fields they will match if they are set and
not match if they aren't set.

In general fields that aren't required will not be available, rather
than be empty - e.g. a Connect.WillTopic won't be available rather than
being an empty string if the field isn't specified, this is to make it
possible to make rules that handle a specified field without content
from a field that isn't in the message.

Fields that aren't flags/booleans will set the cursor position to the
value of the field.

#### Connect fields

Connect.WillTopic
Connect.WillMessage
Connect.WillQoS
Connect.UserName
Connect.Password
Connect.Flag.WillRetain
Connect.Flag.CleanSession

#### ConnAck fields

ConnAck.ReturnCode

#### Publish fields

Publish.Flag.Retain
Publish.Flag.Dup
Publish.Topic
Publish.MessageIdentifier
Publish.Payload
Publish.QoS

#### PubAck fields

PubAck.MessageIdentifier

#### PubRec fields

PubRec.MessageIdentifier

#### PubReg fields

PubRel.Flag.Dup
PubRel.QoS
PubRel.MessageIdentifier

#### PubComp fields

PubComp.MessageIdentifier

#### Subscribe fields

Subscribe.Flag.Dup
Subscribe.QoS
Subscribe.MessageIdentifier
Subscribe.SubscribeCount     - Number of items in the subscribe list
Subscribe.Payload            - Alias for Subscribe.Topic
Subscribe.Topic              - As a subscribe topic can contain a list
                               of topics, the match/regex logic will be
                               executed on each individual topic in the
                               list

#### SubAck fields
SubAck.MessageIdentifier
SubAck.GrantedCount
SubAck.Payload


#### Unsubscribe fields
Unsubscribe.Flag.Dup
Unsubscribe.QoS
Unsubscribe.MessageIdentifier
Unsubscribe.UnsubscribeCount - Number of items in the unsubscribe list
Unsubscribe.Payload          - Alias for Unsubscribe.Topic
Unsubscribe.Topic            - As an unsubscribe topic can contain a 
                               list of topics, the match/regex logic 
                               will be executed on each individual topic
                               in the list

#### UnsubAck fields
 
UnsubAck.MessageIdentifier
