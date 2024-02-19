# Karloss_v2 main

# Imports
from pktImport import Packets
from analysis import analyse_packet
import datetime
from multiprocessing import Pool
import psutil
from functools import partial

def process_packet(packet, msgDicts, summary):
    pkt_analysed, summary = analyse_packet(packet, summary, msgDicts)
    return pkt_analysed, summary

if __name__ == "__main__":
    num_cpus = psutil.cpu_count(logical=False)
    pool = Pool(num_cpus)

    time_start = datetime.datetime.now()

    pktClass = Packets(input_file='./pcap/test4.pcap')
    packets = pktClass.get_packet_array()

    msgDicts = {}
    for msgType in pktClass.get_msg_types().values():
        msgDicts[msgType[1]] = msgType[0].get_dictionary()

    summary = {}  # Initialize summary here
    partial_process_packet = partial(process_packet, msgDicts=msgDicts, summary=summary)
    results = pool.map(partial_process_packet, packets)
    pktsAnalysed, summary = zip(*results)

    time_end = datetime.datetime.now()

    print(f'Duration: {(time_end - time_start).total_seconds() / 60} min; Packets analysed: {len(packets)}')
