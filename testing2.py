import datetime
from pktImport import Packets
from analysis import analyse_packet


# Print iterations progress
def printProgressBar(iteration, total, prefix='', suffix='', decimals=1, length=100, fill='█', printEnd="\r"):
    """
    Call in a loop to create terminal progress bar
    @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        length      - Optional  : character length of bar (Int)
        fill        - Optional  : bar fill character (Str)
        printEnd    - Optional  : end character (e.g. "\r", "\r\n") (Str)
    """
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filledLength = int(length * iteration // total)
    bar = fill * filledLength + '-' * (length - filledLength)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end=printEnd)
    # Print New Line on Complete
    if iteration == total:
        print()


pkts_analysed = []
input_file = './pcap/test4.pcap'
config_location = './config.json'

time_start = datetime.datetime.now()
print('Importing packets...', end='')
packet_object = Packets(input_file=input_file, config_location=config_location)
packet_array = packet_object.get_packet_array()
time_end = datetime.datetime.now()
print(f' done in {(time_end - time_start).total_seconds()} seconds.')

time_start = datetime.datetime.now()
print('Rebuilding asn dictionaries...', end='')
asn_dictionaries = packet_object.get_its_msg_dict(msg_name_key=True, asn_values=True)
time_end = datetime.datetime.now()
print(f' done in {(time_end - time_start).total_seconds()} seconds.')

print('Analysing packets...')
summary = {}
time_analysis_start = datetime.datetime.now()

for idx, pkt in enumerate(packet_array):
    time_packet_start = datetime.datetime.now()
    if isinstance(pkt, dict):
        packet_msg_type = list(pkt.keys())[0]
        asn_dictionary = asn_dictionaries.get(packet_msg_type)
        pkt_analysed, summary = analyse_packet(pkt, asn_dictionary, summary)
        pkts_analysed.append(pkt_analysed)

        time_packet_end = datetime.datetime.now()
        print(
            f'{packet_msg_type} packet {idx+1}/{len(packet_array)} analysed in {(time_packet_end - time_packet_start).total_seconds()} seconds.')
    else:
        pkts_analysed.append(pkt)
        time_packet_end = datetime.datetime.now()
        print(
            f'Packet {idx+1}/{len(packet_array)} was not analysed ({(time_packet_end - time_packet_start).total_seconds()} s). The reason was: {pkt}')
    i += 1

time_analysis_end = datetime.datetime.now()
print('-----------------------------------\n'
      f'Duration: {(time_analysis_end - time_analysis_start).total_seconds() / 60} min; Packets analysed: {len(packet_array)}')


