#!/usr/bin/env python3

# To get scapy on your (Ubuntu) system:
#
#   $ sudo apt install python3-scapy
#
from scapy.all import *
from scapy.contrib.mqtt import *

print("Generating test pcaps")

SERVER_IP = "10.0.2.16"
SERVER_PORT = 1883
CLIENT_IP = "10.0.2.1"
CLIENT_PORT = 4800

class TCPConnection:
  def __init__(self, server_ip, server_port, client_ip, client_port, packets):
    self.server_ip = server_ip
    self.server_port = server_port
    self.client_ip = client_ip
    self.client_port = client_port
    self.packets = packets
    self.client_seq = 10000  
    self.server_seq = 50000  


  def packet_to_client(self, flags):
    packet = IP()/TCP(flags=flags)
    packet.src = self.server_ip
    packet.dst = self.client_ip
    packet.sport = self.server_port
    packet.dport = self.client_port
    return packet

  def packet_to_server(self, flags):
    packet = IP()/TCP(flags=flags)
    packet.src = self.client_ip
    packet.dst = self.server_ip
    packet.sport = self.client_port
    packet.dport = self.server_port
    return packet

  def tcp_connect(self):
    to_server = self.packet_to_server(flags="S")
    
    to_server.seq=self.client_seq

    self.packets.append(to_server)

    self.client_seq += 1

    to_client = self.packet_to_client(flags="SA")
    
    to_client.seq = self.server_seq
    to_client.ack = self.client_seq

    self.packets.append(to_client)

    self.server_seq += 1

    to_server = self.packet_to_server(flags="A")
    
    to_server.seq = self.client_seq
    to_server.ack = self.server_seq

    self.packets.append(to_server)

  def client_initiated_tcp_disconnect(self):
    to_server = self.packet_to_server(flags="FA")

    to_server.seq = self.client_seq
    to_server.ack = self.server_seq

    self.packets.append(to_server)

    self.client_seq += 1

    to_client = self.packet_to_client(flags="FA")

    to_client.seq = self.server_seq
    to_client.ack = self.client_seq

    self.packets.append(to_client)

    self.server_seq += 1
    
    to_server = self.packet_to_server(flags="A")

    to_server.seq = self.client_seq
    to_server.ack = self.server_seq

    self.packets.append(to_server)

  def to_server(self, data):
    to_server = self.packet_to_server(flags="PA") / data

    to_server.seq = self.client_seq
    to_server.ack = self.server_seq

    self.packets.append(to_server)

    self.client_seq += len(data)

  def to_client(self, data):
    to_client = self.packet_to_client(flags="PA") / data

    to_client.seq = self.server_seq
    to_client.ack = self.client_seq

    self.packets.append(to_client)
  
    self.server_seq += len(data)
  

#### Generate Connect test

data = []

# Connect with 3.1               
connection = TCPConnection(server_ip=SERVER_IP,
                           server_port=SERVER_PORT,
                           client_ip=CLIENT_IP,
                           client_port=CLIENT_PORT,
                           packets=data)

connection.tcp_connect()
connection.to_server(MQTT(type=1) / MQTTConnect(protoname="MQIsdp", protolevel=3, clientId="Client 3.1"))
connection.to_client(MQTT(type=2) / MQTTConnack())
connection.client_initiated_tcp_disconnect()

# Connect with 3.1.1
connection = TCPConnection(server_ip=SERVER_IP,
                           server_port=SERVER_PORT,
                           client_ip=CLIENT_IP,
                           client_port=CLIENT_PORT + 1,
                           packets=data)

connection.tcp_connect()
connection.to_server(MQTT(type=1) / MQTTConnect(protoname="MQTT", protolevel=4, clientId="Client 3.1.1"))
connection.to_client(MQTT(type=2) / MQTTConnack())
connection.client_initiated_tcp_disconnect()

# Connect with 5.0
connection = TCPConnection(server_ip=SERVER_IP,
                           server_port=SERVER_PORT,
                           client_ip=CLIENT_IP,
                           client_port=CLIENT_PORT + 2,
                           packets=data)

connection.tcp_connect()
connection.to_server(MQTT(type=1) / MQTTConnect(protoname="MQTT", protolevel=5, clientId="Client 5.0"))
connection.to_client(MQTT(type=2) / MQTTConnack())
connection.client_initiated_tcp_disconnect()

wrpcap("testdata/test_connect.pcap", data)

### MATCH Test

data = []
connection1 = TCPConnection(server_ip=SERVER_IP,
                            server_port=SERVER_PORT,
                            client_ip=CLIENT_IP,
                            client_port=1,
                            packets=data)

connection2 = TCPConnection(server_ip=SERVER_IP,
                            server_port=SERVER_PORT,
                            client_ip=CLIENT_IP,
                            client_port=2,
                            packets=data)

connection3 = TCPConnection(server_ip=SERVER_IP,
                            server_port=SERVER_PORT,
                            client_ip=CLIENT_IP,
                            client_port=3,
                            packets=data)

connection4 = TCPConnection(server_ip=SERVER_IP,
                            server_port=SERVER_PORT,
                            client_ip=CLIENT_IP,
                            client_port=4,
                            packets=data)

connection5 = TCPConnection(server_ip=SERVER_IP,
                            server_port=SERVER_PORT,
                            client_ip=CLIENT_IP,
                            client_port=5,
                            packets=data)


# Connect with 3.1           
connection1.tcp_connect()
connection1.to_server(MQTT(type=1) / MQTTConnect(protoname="MQIsdp", protolevel=3, clientId="Client 1"))
connection1.to_client(MQTT(type=2) / MQTTConnack())

connection2.tcp_connect()
connection2.to_server(MQTT(type=1) / MQTTConnect(protoname="MQIsdp", protolevel=3, clientId="Client 2"))
connection2.to_client(MQTT(type=2) / MQTTConnack())

connection3.tcp_connect()
connection3.to_server(MQTT(type=1) / MQTTConnect(protoname="MQIsdp", protolevel=3, clientId="Client 3"))
connection3.to_client(MQTT(type=2) / MQTTConnack())

connection4.tcp_connect()
connection4.to_server(MQTT(type=1) / MQTTConnect(protoname="MQIsdp", protolevel=3, clientId="Client 4"))
connection4.to_client(MQTT(type=2) / MQTTConnack())

connection5.tcp_connect()
connection5.to_server(MQTT(type=1) / MQTTConnect(protoname="MQIsdp", protolevel=3, clientId="Client 5"))
connection5.to_client(MQTT(type=2) / MQTTConnack())


# Make subscription



connection1.to_server(MQTT(type=8, QOS=1) / MQTTSubscribe(msgid=0xFFFF, topics = [
                                                                  MQTTTopicQOS(topic="level1/level2", QOS=0),
                                                                  MQTTTopicQOS(topic="A/+/B", QOS=2),
                                                                  MQTTTopicQOS(topic="A/B/C", QOS=1),
                                                                  MQTTTopicQOS(topic="C/+/#"),
                                                                  MQTTTopicQOS(topic="/A/C")
                                                                ]))

connection2.to_server(MQTT(type=8, QOS=1) / MQTTSubscribe(msgid=0x1,    topics = [
                                                                  MQTTTopicQOS(topic="/D"),
                                                                  MQTTTopicQOS(topic="A/B/C/"),
                                                                  MQTTTopicQOS(topic="/A/Aa/B"),
                                                                  MQTTTopicQOS(topic="level/level")
                                                                  
                                                                ]))

connection3.to_server(MQTT(type=8, QOS=1) / MQTTSubscribe(msgid=0x2,    topics = [
                                                                  MQTTTopicQOS(topic="/A/B/C"),
                                                                  MQTTTopicQOS(topic="A/D/C"),
                                                                  MQTTTopicQOS(topic="/A/Aa/B"),
                                                                  MQTTTopicQOS(topic="/D")
                                                                ]))

connection4.to_server(MQTT(type=8, QOS=1) / MQTTSubscribe(msgid=0x3,    topics = [
                                                                  MQTTTopicQOS(topic="/A/B/C"),
                                                                ]))


connection5.to_server(MQTT(type=8, QOS=1) / MQTTSubscribe(msgid=0x4,    topics = [
                                                                  MQTTTopicQOS(topic="#", QOS=1),
                                                                ]))

                                                                

# Server response
connection1.to_client(MQTT(type=9) / MQTTSuback(msgid=0xFFFF, retcodes=[0,2,1,0,0]))
connection2.to_client(MQTT(type=9) / MQTTSuback(msgid=0x1, retcodes=[0,0,0,0]))
connection3.to_client(MQTT(type=9) / MQTTSuback(msgid=0x2, retcodes=[0,0,0,0]))
connection4.to_client(MQTT(type=9) / MQTTSuback(msgid=0x2, retcodes=[0]))
connection5.to_client(MQTT(type=9) / MQTTSuback(msgid=0x2, retcodes=[0]))

# Clean disconnect
connection1.to_server(MQTT(type=14) / MQTTDisconnect())
connection1.client_initiated_tcp_disconnect()
connection2.to_server(MQTT(type=14) / MQTTDisconnect())
connection2.client_initiated_tcp_disconnect()
connection3.to_server(MQTT(type=14) / MQTTDisconnect())
connection3.client_initiated_tcp_disconnect()
connection4.to_server(MQTT(type=14) / MQTTDisconnect())
connection4.client_initiated_tcp_disconnect()
connection5.to_server(MQTT(type=14) / MQTTDisconnect())
connection5.client_initiated_tcp_disconnect()


wrpcap("testdata/mqtt_subscribe.pcap", data)
                                                                    
### RegEx test

### Splitter test

### All types test...

### All rules test...

### Flags test

### Client id with new ip

### Subscribe with QOS = 0, must not have msgid
