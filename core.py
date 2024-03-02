import json
from pktImport import Packets
from plugins.msg import ItsMessage
from analysis import analyse_packet

class Karloss(object):
    def __init__(self, input_file, config_location='./config.json'):
        packet_object = Packets(input_file=input_file, config_location=config_location)
        self.packet_array = packet_object.get_packet_array()
        self.asn_dictionaries = packet_object.get_its_msg_dict(msg_name_key=True, asn_values=True)

    def analyse(self):
        pkts_analysed = []
        for pkt in self.packet_array:
            packet_msg_type = list(pkt.keys())[0]
            asn_dictionary = self.asn_dictionaries.get(packet_msg_type)
            pkt_analysed, summary = analyse_packet(pkt, asn_dictionary, summary)
            pkts_analysed.append(pkt_analysed)
        return pkts_analysed, summary
