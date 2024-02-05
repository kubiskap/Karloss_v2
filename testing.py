from pktImport import recursive_parameters
from pktImport import Packets
import dpath


pktClass = Packets(input_file='./test.pcap')
packets = pktClass.get_packet_array()
pkt = packets[27]

for path, key, value in recursive_parameters(pkt):
    pktTest = pkt
    print(f"{key} -- {value} -- {path}")
