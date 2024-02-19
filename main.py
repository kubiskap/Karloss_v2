# Karloss_v2 main

# Imports
from pktImport import Packets
from analysis import analyse_packet
import datetime
from multiprocessing import Pool
import psutil

num_cpus = psutil.cpu_count(logical=False)
summary = {}
pktsAnalysed = []
pool = Pool(num_cpus)

time_start = datetime.datetime.now()

pktClass = Packets(input_file='./pcap/test.pcap')
packets = pktClass.get_packet_array()

msgDicts = {}
for msgType in pktClass.get_msg_types().values():
    msgDicts[msgType[1]] = msgType[0].get_dictionary()

for pkt in packets:
    pkt_analysed, summary = analyse_packet(pkt, summary, msgDicts)
    pktsAnalysed.append(pkt_analysed)

time_end = datetime.datetime.now()

print(f'Duration: {(time_end-time_start).total_seconds()/60} min; Packets analysed: {len(packets)}')
