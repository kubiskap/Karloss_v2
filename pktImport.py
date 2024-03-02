import pyshark
import json
from plugins.msg import ItsMessage
from asnprocessor import AsnDictProcessor


class Packets(object):
    def __init__(self,
                 input_file,
                 config_location):
        self.input_file = input_file
        self.pcap = pyshark.FileCapture(self.input_file, include_raw=True, use_json=True)
        self.config_location = config_location
        with open(self.config_location, 'r') as f:
            self.config = json.loads(f.read())

    def get_its_msg_dict(self, msg_name_key=False, asn_values=False):  # Establish ItsMessage object for every type of msg in config
        configured_msgs = {}
        for msg_port, config_value in self.config['msgPorts'].items():
            dict_key = config_value['msgName'] if msg_name_key else msg_port
            its_message_object = ItsMessage(asn_files=config_value['asnFiles'], msg_name=config_value['msgName'])
            configured_msgs[dict_key] = its_message_object.asn_rebuilt if asn_values else its_message_object
        return configured_msgs

    def get_packet_array(self):  # Method to decode all packets in "input_file" and stack them into a list
        packet_array = []
        msg_types = self.get_its_msg_dict()
        for idx, pkt in enumerate(self.pcap):
            if 'MALFORMED' in str(pkt.layers):
                packet_array.append(f'Packet no. {idx + 1}: malformed packet')
            elif 'ITS' in str(pkt.layers):
                try:
                    msg_object = msg_types.get(pkt.btpb.dstport)
                    pkt_decoded = msg_object.decode(bytes.fromhex(pkt.its_raw.value))
                    if len(pkt_decoded) != 0:
                        packet_array.append(pkt_decoded)
                    else:
                        packet_array.append(f'Packet no. {idx + 1}: decode/constraint error')
                except KeyError:
                    packet_array.append(f'Packet no. {idx + 1}: unsupported message type with dstport {pkt.btpb.dstport}.')
        return packet_array


def process_list(input_list):
    output_dict = {}
    for index, item in enumerate(input_list):
        if isinstance(item, list):
            output_dict[f'listItem{index}'] = process_list(item)
        elif isinstance(item, dict):
            output_dict[f'listItem{index}'] = process_packet(item)
        else:
            output_dict[f'listItem{index}'] = item
    return output_dict


def process_packet(input_dict):
    output_dict = {}
    for key, value in input_dict.items():
        # Convert CHOICE, which returns (str, object), to {str: object}
        if isinstance(value, tuple) and len(value) == 2 and isinstance(value[0], str):
            output_dict[key] = process_packet({value[0]: value[1]})
        # Convert BIT STRING, which returns (bytes, int) to bits
        elif isinstance(value, tuple) and len(value) == 2 and isinstance(value[0], bytes) and isinstance(value[1], int):
            binary_string = ''.join(format(byte, '08b') for byte in value[0])
            binary = binary_string[:value[1]]
            output_dict[key] = binary
        # Convert nested lists into dictionary
        elif isinstance(value, list):
            output_dict[key] = process_list(value)
        # If value is dict, go one level deeper
        elif isinstance(value, dict):
            output_dict[key] = process_packet(value)
        else:
            output_dict[key] = value
    return output_dict


def recursive_parameters(packet, path=None): # Generator used to iterate through every parameter of the packet
    if path is None:
        path = []
    for key, value in packet.items():
        if isinstance(value, dict):
            yield from recursive_parameters(value, path + [key])
        elif isinstance(value, list):
            for index, item in enumerate(value):
                yield from recursive_parameters(item, path + [key] + [index])
        yield (path + [key], key, value)