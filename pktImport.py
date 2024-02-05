import pyshark
from plugins.msg import *


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
                    pkts.append(f'Packet no. {idx + 1}: unsupported message type')
        return pkts


def recursive_parameters(packet, path=[]):  # Method to
    for key, value in packet.items():
        if type(value) is dict:
            yield from recursive_parameters(value, path + [key])
        if type(value) is tuple:
            yield (path + [key], key, value)
        if type(value) is tuple and type(value[0]) is str and type(value[1]) is dict:
            yield from recursive_parameters(value[1], path + [key])
        else:
            yield (path + [key], key, value)

