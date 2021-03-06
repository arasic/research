#!/usr/bin/env python
import socket, struct, os, array, time, netifaces, binascii, datetime
from scapy.all import ETH_P_ALL
from scapy.all import select
from scapy.all import MTU
from cassandraDB import CassandraDB
from time import sleep
import uuid

traffic_in = {}
traffic_out = {}

updateIntervalTime = None
UPDATE_TIME_LIMIT = 60

cassandraDB = None
counter = 10

class NetworkFlow:
    networkFlow = {}
    def __init__(self, mac_src, mac_dst, ip_src, port_src, ip_dst, port_dst, pkt_size, proto):
        self.time = time
        self.mac_src = mac_src
        self.mac_dst = mac_dst
        self.ip_src = ip_src
        self.port_src = port_src
        self.ip_dst = ip_dst
        self.port_dst = port_dst
        # Protocols can be found at : 
        # http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
        self.proto = proto
        self.total_size = pkt_size
        self.count = 1
        self.time = time.time()
        self.generateduuid = uuid.uuid1()

    def add(self, size, count):
        self.total_size += size
        self.count += 1
        self.time = time.time()

    def get_width(self, value):
        tabs ="\t"
        if len(value) < 15:
            tabs +="\t"
        return tabs

    def __str__(self):
        msg = ""
        msg += "%s:%s" % (self.ip_src, self.port_src)
        msg += self.get_width(str(self.ip_src) + str(self.port_src))
        msg += "(%s)" % self.mac_src
        msg += self.get_width(self.mac_src)
        msg += "%s:%s" % (self.ip_dst, self.port_dst)
        msg += self.get_width(str(self.ip_dst) +  str(self.port_dst))
        msg += "(%s)" % self.mac_dst
        msg += self.get_width(self.mac_dst)
        msg += "%s\t" % self.count
        msg += "%s\t\t" % self.proto
        msg += "%s" % sizeof_fmt(self.total_size)
        msg += self.get_width(str(self.total_size))
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

def get_src_mac(pkt):
    return "%x:%x:%x:%x:%x:%x".upper() % struct.unpack("BBBBBB",pkt[6:12])

def get_dst_mac(pkt):
    return "%x:%x:%x:%x:%x:%x".upper() % struct.unpack("BBBBBB",pkt[0:6])

# More info on ether types at : 
# http://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
# https://en.wikipedia.org/wiki/EtherType
def get_ether_type(pkt):
#    return binascii.hexlify(pkt[12:14]).decode()
    return "0x0%x" % struct.unpack('!H', pkt[12:14])

def get_payload(pkt):
    return pkt[14:]
#    return binascii.hexlify(pkt[14:]).decode()

def print_dict_values(network_dict):
    for key in network_dict.keys():
        print network_dict[key]

# Probably one of the most elegant way to display data size in human readable
# unit.
def sizeof_fmt(num, suffix='B'):
    for unit in ['','K','M','G','T','P','E','Z']:
        if abs(num) < 1024.0:
            return "%3.1f\t%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f\t%s%s" % (num, 'Y', suffix)


# Give user the option to choose the interface ?
def get_interface():
    for iface in netifaces.interfaces():
        address = netifaces.ifaddresses(iface)
        print "iface:%s" % iface
        if iface.lower() == "lo".lower():
            continue
#        print "address : %s\n" % address
        try:
#            address_af_link = address[netifaces.AF_LINK][0]
#            print "aflink:%s" % address_af_link
#            if address_af_link is not None:
#                if_mac = address[netifaces.AF_LINK][0]['addr']

#            address_af_inet = address[netifaces.AF_INET][0]
#            print "afinet:%s" % address_af_inet
#            if address_af_inet is not None:
#                if_ip = address[netifaces.AF_INET][0]['addr']
#            print '%s : %s / %s' % (iface, if_mac, if_ip)
#            if if_ip.startswith("192.") or if_ip.startswith("172."):
            print 'Choosing interface %s' % iface
            return iface
        except Exception, ex:
            print 'cant solve %s' % iface
            print ex
            pass
    return interface_name

# TODO : Need to capt dns requests
def main():
    global updateIntervalTime
    updateIntervalTime = time.time()
    interface_name = get_interface()
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
        payload = get_payload(pkt)
#        print "Ether type : %s" % get_ether_type(pkt)
#
        process_ipframe(sa_ll[2], ip_header, payload, pkt)

def incoming_callback(time, src_mac, dst_mac, ip_src, port_src, ip_dst, port_dst, proto,pkt_size, frame):
  #pass
#    srcIP = socket.inet_ntoa(src)
#    dstIP = socket.inet_ntoa(dst)
#    print("incoming - src=%s, dst=%s, frame len = %d"
#        %(srcIP, dstIP, len(frame)))
    addressTuple = ip_src+":"+str(port_src)+"-"+ip_dst+":"+str(port_dst)
    if addressTuple not in traffic_in:
        mac_src = src_mac
        mac_dst = dst_mac
        traffic_in[addressTuple] = NetworkFlow(
              mac_src, 
              mac_dst, 
              ip_src, 
              port_src, 
              ip_dst, 
              port_dst,
              pkt_size,
              proto)

        print "traffic_in: adding %s" % addressTuple
    else:
        traffic_in[addressTuple].add(pkt_size,1)

def outgoing_callback(time, src_mac, dst_mac, ip_src, port_src, ip_dst, port_dst, proto,pkt_size, frame):
  #pass
#    srcIP = socket.inet_ntoa(src)
#    dstIP = socket.inet_ntoa(dst)
#    print("outgoing - src=%s, dst=%s, frame len = %d"
#        %(srcIP, dstIP, len(frame)))
    addressTuple = ip_src+":"+str(port_src)+"-"+ip_dst+":"+str(port_dst)
    if addressTuple not in traffic_out:
        mac_src = src_mac
        mac_dst = dst_mac
        traffic_out[addressTuple] = NetworkFlow(
              mac_src,
              mac_dst,
              ip_src,
              port_src,
              ip_dst,
              port_dst,
              pkt_size,
              proto)

        print "traffic_out: adding %s" % addressTuple
    else:
        traffic_out[addressTuple].add(pkt_size,1)

def execute_query(batch_query):
    global cassandraDB
    try:
#        sleep(0.5)
        cassandraDB.query(batch_query)
    except IOError, error:
        print IOError, error
        cassandraDB = CassandraDB("192.168.2.4")
        print "trying again.."
        cassandraDB.query(batch_query)

def store_traffic(traffic_map):
    maxQueryLength = 10000
#    batchQuery = "BEGIN BATCH "
    batchQuery = ""
    lstQueries = []
    for entry_key,entry_value in traffic_map.items():
        currenttime = datetime.datetime.utcnow().isoformat()[:-3]
        insertQuery = (("insert into test.traffic4 "
        "(insertion_time, uuid, src_ip, src_port, src_mac_addr, dst_ip,"
        "dst_port, dst_mac_addr, packets, protocol, data_size) "
        "values('%s', %s, '%s', %d, '%s', '%s', %d, '%s', %d, %d, %d);")
         % (currenttime, entry_value.generateduuid, entry_value.ip_src, entry_value.port_src,
            entry_value.mac_src, entry_value.ip_dst, entry_value.port_dst,
            entry_value.mac_dst, entry_value.count, entry_value.proto, entry_value.total_size))
        lstQueries.append(insertQuery)
    
        del traffic_map[entry_key]

        if len(lstQueries) > maxQueryLength:
#            batchQuery += " APPLY BATCH;"
            execute_query(lstQueries)
            lstQueries = []
#            batchQuery = "BEGIN BATCH "
#    batchQuery += " APPLY BATCH;"
    execute_query(lstQueries)
    print "traffic-map size = %d " % len(traffic_map)

def process_ipframe( pkt_type, ip_header, payload, pkt):
    
    global updateIntervalTime
    global counter
    global cassandraDB
    # Extract the 20 bytes IP header, ignoring the IP options
    fields = struct.unpack("!BBHHHBBHII", ip_header)

    dummy_hdrlen = fields[0] & 0xf
    iplen = fields[2]

#    ip_src = payload[12:16]
#    ip_dst = payload[16:20]
#    ip_src2, ip_dst2 = get_ips(payload)
    src_mac = get_src_mac(pkt)
    dst_mac = get_dst_mac(pkt)
    ip_src,port_src,ip_dst,port_dst,proto = get_pkt_info(payload)


    #time
#    currentTimeNow = datetime.datetime.now()
#    currentTime = currentTimeNow.time()
#    print "current time now %s" % currentTimeNow
#    print "current time %s" % currentTime

    currentTime = time.time()
    counter = counter-1

    if(counter <= 0 or updateIntervalTime < currentTime):
        if len(traffic_out) > 0:
            counter = 10000
        print "perform display..dumping data in DB"
        updateIntervalTime = currentTime + UPDATE_TIME_LIMIT
        print "time set to %s " % updateIntervalTime
#        import pdb;pdb.set_trace()
        if not cassandraDB:
            cassandraDB = CassandraDB("192.168.2.4")
		
        store_traffic(traffic_out)
        store_traffic(traffic_in)
        
#        cassandraDB.shutdownSession()

    #print "current time %s" % currentTime

    if port_dst == 53:
        print payload
#       import pdb;pdb.set_trace()
    payload_size = len(payload)
#    print 'packet size %s' % packet_size
    ip_frame = payload[0:iplen]
    if pkt_type == socket.PACKET_OUTGOING:
#        if on_ip_outgoing is not None:
            incoming_callback(currentTime, src_mac, dst_mac, ip_src,port_src,ip_dst,port_dst,proto,payload_size, ip_frame)

    else:
#        if on_ip_incoming is not None:
            outgoing_callback(currentTime, src_mac, dst_mac, ip_src,port_src,ip_dst,port_dst,proto,payload_size, ip_frame)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print 'Traffic in(%s), traffic out(%s)' % (len(traffic_in),
                len(traffic_out))
        print 'printing traffic in.'
        print 'ip src:port\t\tsrc-mac\t\t\tip dst:port\t\tdst-mac\t\t\thits\tprotocol\tdata'
        print_dict_values(traffic_in)
        print 'printing traffic out.'
        print_dict_values(traffic_out)
        print 'Stopping process..'
    except Exception, err:
        print 'An Exception has occurred.'
        print Exception, err

