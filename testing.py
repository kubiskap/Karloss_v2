from pktImport import recursive_parameters
from pktImport import deal_with_choice_type
from pktImport import Packets
import dpath
import copy

pktClass = Packets(input_file='./pcap/test.pcap')
packets = pktClass.get_packet_array()
pkt = packets[0]
pktTest = copy.deepcopy(pkt)

pktModified = deal_with_choice_type(pkt)

for path, key, value in recursive_parameters(pktModified):
    print(f"{key} -- {value} -- {path}")
