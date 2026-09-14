# Overall

The files in this folder defines a series of plugins that can be used
to parse and make rules for mqtt network traffic

The inspector knows about MQTT 3.1, 3.1.1 and 5.0 standards (protocol
versions 3, 4 and 5) other protocol numbers will be rejected, however
it can only interpret messages (beyond the msg type ID) from version 3.1


Examples of alerts:

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
        mqtt_field: ConnAck.ReturnCode, range_match "=4";
        sid: 3100012;
      )
    
      generates an alert on all connection attempts where the username/password was rejected by the server

