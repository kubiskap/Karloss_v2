import pyshark
from plugins.msg import *
import dpath
import copy


class Packets(object):
    def __init__(self,
                 input_file,
                 config_location='./config.json'):
        self.input_file = input_file
        self.pcap = pyshark.FileCapture(self.input_file, include_raw=True, use_json=True)
        self.config_location = config_location
        with open(self.config_location, 'r') as f:
            self.config = json.loads(f.read())

    def get_msg_types(self):  # Establish ItsMessage object for every type of msg in config
        msgTypes = {}
        for i in self.config['msgPorts']:
            msgTypes[i] = [ItsMessage(msg_type=self.config['msgPorts'][i]['msgName'],
                                      asn_file=self.config['msgPorts'][i]['asnFiles']),
                           self.config['msgPorts'][i]['msgName']]
        return msgTypes

    def get_packet_array(self):  # Method to decode all packets in "input_file" and stack them into a list
        pkts = []
        msgTypes = self.get_msg_types()
        for idx, pkt in enumerate(self.pcap):
            if 'MALFORMED' in str(pkt.layers):
                pkts.append(f'Packet no. {idx + 1}: malformed packet')
            elif 'ITS' in str(pkt.layers):
                try:
                    msgFunc = msgTypes.get(pkt.btpb.dstport)[0]
                    msgName = msgTypes.get(pkt.btpb.dstport)[1]
                    pkt_decoded = msgFunc.decode(bytes.fromhex(pkt.its_raw.value))
                    if len(pkt_decoded) != 0:
                        pkts.append(pkt_decoded)
                    else:
                        pkts.append(f'Packet no. {idx + 1}: {msgName} decode/constraint error')
                except KeyError:
                    pkts.append(f'Packet no. {idx + 1}: unsupported message type with dstport {pkt.btpb.dstport}.')
        return pkts


def deal_with_choice_type(input_dict):  # Convert CHOICE, which returns (str, object), to {str: object}
    output_dict = {}
    for key, value in input_dict.items():
        if isinstance(value, tuple) and len(value) == 2 and isinstance(value[0], str) and isinstance(value[1], dict):
            output_dict[key] = {value[0]: deal_with_choice_type(value[1])}
        elif isinstance(value, dict):
            output_dict[key] = deal_with_choice_type(value)
        else:
            output_dict[key] = value
    return output_dict


def recursive_parameters(packet, path=[]): # Generator function used to iterate through every parameter of the packet
    for key, value in packet.items():
        if isinstance(value, dict):
            yield from recursive_parameters(value, path + [key])
        yield (path + [key], key, value)