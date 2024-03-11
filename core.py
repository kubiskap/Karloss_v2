import datetime
from pktImport import Packets
from analysis import analyse_packet


class Karloss(object):
    def __init__(self, input_file, config_location='./config.json'):
        self.pkts_analysed = []
        packet_object = Packets(input_file=input_file, config_location=config_location)
        self.packet_array = packet_object.get_packet_array()
        self.asn_dictionaries = packet_object.get_its_msg_dict(msg_name_key=True, asn_values=True)
        self.summary = {}

    def analyse(self):
        time_start = datetime.datetime.now()
        for pkt in self.packet_array:
            if isinstance(pkt, dict):
                packet_msg_type = list(pkt.keys())[0]
                asn_dictionary = self.asn_dictionaries.get(packet_msg_type)
                pkt_analysed, self.summary = analyse_packet(pkt, asn_dictionary, self.summary)
                self.pkts_analysed.append(pkt_analysed)
            else:
                self.pkts_analysed.append(pkt)
        time_end = datetime.datetime.now()
        print(f'Duration: {(time_end - time_start).total_seconds() / 60} min; Packets analysed: {len(self.packet_array)}')