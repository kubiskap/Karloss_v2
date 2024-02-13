from pktImport import recursive_parameters
from pktImport import process_packet
from pktImport import Packets
import dpath
import copy
from typing import Union, Dict, List, Tuple



pktClass = Packets(input_file='./pcap/testmon5.pcap')
packets = pktClass.get_packet_array()
pkt = packets[5]
pktTest = copy.deepcopy(pkt)

pktModified = process_packet(pkt)

#for path, key, value in recursive_parameters(pktModified):
#    print(f"{key} -- {value} -- {path}")

