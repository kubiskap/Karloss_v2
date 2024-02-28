# Karloss_v2 main

# Imports
from pktImport import Packets
from analysis import analyse_packet
import datetime
from multiprocessing import Pool
import psutil
from functools import partial


def process_packet(packet, msg_dict, summary_dict):
    pkt_analysed, summary = analyse_packet(packet, summary_dict, msg_dict)
    return pkt_analysed, summary


if __name__ == "__main__":
    num_cpus = psutil.cpu_count(logical=False)
    pool = Pool(num_cpus)

    time_start = datetime.datetime.now()

    pktClass = Packets(input_file='./pcap/test4.pcap', config_location='./config.json')
    packets = pktClass.get_packet_array()

    msg_dicts = pktClass.get_its_msg_object_dict(msg_name_key=True)

    summary = {}  # Initialize summary here
    partial_process_packet = partial(process_packet, msg_dict=msg_dicts, summary_dict=summary)
    results = pool.map(partial_process_packet, packets)
    pktsAnalysed, summary = zip(*results)

    time_end = datetime.datetime.now()

    print(f'Duration: {(time_end - time_start).total_seconds() / 60} min; Packets analysed: {len(packets)}')
