from core import Karloss
from analysis import analyse_packet

karloss = Karloss(input_file='./pcap/testmon6.pcap')
summary = []
pkt_analysed, summary = analyse_packet(karloss.packet_array[1075], karloss.asn_dictionaries['CAM'], summary)
