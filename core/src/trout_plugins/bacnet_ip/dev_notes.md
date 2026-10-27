BACnet/IP
*********

This module is under development, and might change significantly


The anatomy of a BACnet/IP packet:

Ethernet frame
-IP packet
--UDP datagram
---BVLC header
----NPDU  <-- takes care of addressing and routing
-----APDU <-- Payload

This plugin is mainly concerned with the NPDU layer
