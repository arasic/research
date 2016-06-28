import socket, struct, os, array, time
from scapy.all import ETH_P_ALL
from scapy.all import select
from scapy.all import MTU

traffic_in = {}
traffic_out = {}

class NetworkFlow:
    networkFlow = {}
    def __init__(self, mac_src, mac_dst, ip_src, port_src, ip_dst, port_dst, proto):
        self.mac_src = mac_src
        self.mac_dst = mac_dst
        self.ip_src = ip_src
        self.port_src = port_src
        self.ip_dst = ip_dst
        self.port_dst = port_dst
        # Protocols can be found at : 
        # http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
        self.proto = proto
        self.total_size = 0
        self.count = 1
        self.time = int(time.time())
    
    def add(self, size, count):
        self.total_size += size
        self.count += 1
        self.time = int(time.time())

    def get_width(self, ip, port):
        tabs ="\t"
        if (len(str(ip)) + len(str(port))) < 15:
            tabs +="\t"
        return tabs

    def __str__(self):
        msg = ""
        msg += "%s:%s" % (self.ip_src, self.port_src)
        msg += self.get_width(self.ip_src, self.port_src)

        msg += "%s:%s" % (self.ip_dst, self.port_dst)
        msg += self.get_width(self.ip_dst, self.port_dst)

        msg += "%s\t" % self.count
        msg += "%s\t" % self.time
        msg += "%s\t" % self.proto
        return msg

class Sniff:

    def __init__(self, interface_name, incoming, outgoing):

        self.interface_name = interface_name
        self.on_ip_incoming = incoming
        self.on_ip_outgoing = outgoing
       
        # The raw in (listen) socket is a L2 raw socket that listen
        # for all packets going through a specific interface. 
        self.ins = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2*30)
        self.ins.bind((self.interface_name, ETH_P_ALL))

def is_ipv4_tcp_udp(msg):
    # AND off first 4 bits of payload (IP packet) to ensure IP version is 4
    if int(ord(msg[0])) & 0x04 == 4:
        if get_proto(msg) == socket.IPPROTO_TCP or socket.IPPROTO_UDP:
            return True
    return False


def get_pkt_info(msg):
    proto = get_proto(msg)
    ip_src, ip_dst = get_ips(msg)
    port_src, port_dst = get_ports(msg)
    return ip_src, port_src, ip_dst, port_dst, proto


def get_ips(msg):
    # IP source address is bytes 12-16, destination addres is bytes 16-20
    ip_src = socket.inet_ntoa(msg[12:16])
    ip_dst = socket.inet_ntoa(msg[16:20])
    return ip_src, ip_dst


def get_proto(msg):
    # IP protocol number is byte 9
    return ord(msg[9])


def get_ports(msg):
    # TCP/UDP port are first fields in transport header, bytes 20-22 and 22-24
    port_src = struct.unpack('!H', msg[20:22])[0]
    port_dst = struct.unpack('!H', msg[22:24])[0]
    return port_src, port_dst

def print_dict_values(network_dict):
    for key in network_dict.keys():
        print network_dict[key]


def main():
    interface_name = 'eth0'
    on_ip_incoming = incoming_callback
    on_ip_outgoing = outgoing_callback

    # The raw in (listen) socket is a L2 raw socket that listens
    # for all packets going through a specific interface.
    ins = socket.socket(
        socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
    ins.bind((interface_name, ETH_P_ALL))
    while True:
        pkt, sa_ll = ins.recvfrom(MTU)
        if type == socket.PACKET_OUTGOING and on_ip_outgoing is None:
            continue
        elif on_ip_outgoing is None:
            continue
        if len(pkt) <= 0:
            break
        eth_header = struct.unpack("!6s6sH", pkt[0:14])
        dummy_eth_protocol = socket.ntohs(eth_header[2])
        if eth_header[2] != 0x800 :
            continue
        ip_header = pkt[14:34]
        payload = pkt[14:]
        process_ipframe(sa_ll[2], ip_header, payload)

def incoming_callback(ip_src, port_src, ip_dst, port_dst, proto, frame):
  #pass
#    srcIP = socket.inet_ntoa(src)
#    dstIP = socket.inet_ntoa(dst)
#    print("incoming - src=%s, dst=%s, frame len = %d"
#        %(srcIP, dstIP, len(frame)))
    addressTuple = ip_src+':'+ip_dst
    if addressTuple not in traffic_in:
        mac_src = "N/A"
        mac_dst = "N/A"
        traffic_in[addressTuple] = NetworkFlow(
              mac_src, 
              mac_dst, 
              ip_src, 
              port_src, 
              ip_dst, 
              port_dst, 
              proto)

        print "traffic_in: adding %s" % addressTuple
    else:
        traffic_in[addressTuple].add(1,1)

def outgoing_callback(ip_src, port_src, ip_dst, port_dst, proto, frame):
  #pass
#    srcIP = socket.inet_ntoa(src)
#    dstIP = socket.inet_ntoa(dst)
#    print("outgoing - src=%s, dst=%s, frame len = %d"
#        %(srcIP, dstIP, len(frame)))
    addressTuple = ip_src+':'+ip_dst
    if addressTuple not in traffic_out:
        mac_src = "N/A"
        mac_dst = "N/A"
        traffic_out[addressTuple] = NetworkFlow(
              mac_src,
              mac_dst,
              ip_src,
              port_src,
              ip_dst,
              port_dst,
              proto)

        print "traffic_out: adding %s" % addressTuple
    else:
        traffic_out[addressTuple].add(1,1)


def process_ipframe( pkt_type, ip_header, payload):

    # Extract the 20 bytes IP header, ignoring the IP options
    fields = struct.unpack("!BBHHHBBHII", ip_header)

    dummy_hdrlen = fields[0] & 0xf
    iplen = fields[2]

#    ip_src = payload[12:16]
#    ip_dst = payload[16:20]
#    ip_src2, ip_dst2 = get_ips(payload)
    ip_src,port_src,ip_dst,port_dst,proto = get_pkt_info(payload)

    ip_frame = payload[0:iplen]
#    import pdb;pdb.set_trace()
    if pkt_type == socket.PACKET_OUTGOING:
#        if on_ip_outgoing is not None:
            incoming_callback(ip_src,port_src,ip_dst,port_dst,proto, ip_frame)

    else:
#        if on_ip_incoming is not None:
            outgoing_callback(ip_src,port_src,ip_dst,port_dst,proto, ip_frame)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print 'Traffic in(%s), traffic out(%s)' % (len(traffic_in),
                len(traffic_out))
        print 'printing traffic in.'
        print 'ip src:port\t\tip dst:port\t\thits\ttime\t\tprotocol'
        print_dict_values(traffic_in)
        print 'printing traffic out.'
        print_dict_values(traffic_out)
        print 'Stopping process..'
    except Exception:
        print 'an exception has occurred'
