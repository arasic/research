import socket, struct, os, array
from scapy.all import ETH_P_ALL
from scapy.all import select
from scapy.all import MTU

traffic_in = {}
traffic_out = {}
class IPSniff:
 
    def __init__(self, interface_name, on_ip_incoming, on_ip_outgoing):
 
        self.interface_name = interface_name
        self.on_ip_incoming = on_ip_incoming
        self.on_ip_outgoing = on_ip_outgoing
 
        # The raw in (listen) socket is a L2 raw socket that listens
        # for all packets going through a specific interface.
        self.ins = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
        self.ins.bind((self.interface_name, ETH_P_ALL))
 
    def __process_ipframe(self, pkt_type, ip_header, payload):
 
        # Extract the 20 bytes IP header, ignoring the IP options
        fields = struct.unpack("!BBHHHBBHII", ip_header)
 
        dummy_hdrlen = fields[0] & 0xf
        iplen = fields[2]
 
        ip_src = payload[12:16]
        ip_dst = payload[16:20]
        ip_frame = payload[0:iplen]
 
        if pkt_type == socket.PACKET_OUTGOING:
            if self.on_ip_outgoing is not None:
                self.on_ip_outgoing(ip_src, ip_dst, ip_frame)
 
        else:
            if self.on_ip_incoming is not None:
                self.on_ip_incoming(ip_src, ip_dst, ip_frame)
 
    def recv(self):
        while True:
 
            pkt, sa_ll = self.ins.recvfrom(MTU)
 
            if type == socket.PACKET_OUTGOING and self.on_ip_outgoing is None:
                continue
            elif self.on_ip_outgoing is None:
                continue
 
            if len(pkt) <= 0:
                break
 
            eth_header = struct.unpack("!6s6sH", pkt[0:14])
 
            dummy_eth_protocol = socket.ntohs(eth_header[2])
 
            if eth_header[2] != 0x800 :
                continue
 
            ip_header = pkt[14:34]
            payload = pkt[14:]
 
            self.__process_ipframe(sa_ll[2], ip_header, payload)
 
#Example code to use IPSniff
def test_incoming_callback(src, dst, frame):
  #pass
    srcIP = socket.inet_ntoa(src)
    dstIP = socket.inet_ntoa(dst)
#    print("incoming - src=%s, dst=%s, frame len = %d"
#        %(srcIP, dstIP, len(frame)))
    addressTuple = srcIP+':'+dstIP
    if addressTuple not in traffic_in:
      traffic_in[addressTuple] = 1
      print "traffic_in: adding %s" % addressTuple
    else:
      traffic_in[addressTuple] += 1
 
def test_outgoing_callback(src, dst, frame):
  #pass
    srcIP = socket.inet_ntoa(src)
    dstIP = socket.inet_ntoa(dst)
#    print("outgoing - src=%s, dst=%s, frame len = %d"
#        %(srcIP, dstIP, len(frame)))
    addressTuple = srcIP+':'+dstIP
    if addressTuple not in traffic_out:
      traffic_out[addressTuple] = 1
      print "traffic_out: adding %s" % addressTuple
    else:
      traffic_out[addressTuple] += 1
 
ip_sniff = IPSniff('eth0', test_incoming_callback, test_outgoing_callback)
ip_sniff.recv()

