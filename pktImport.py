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

    def get_its_msg_dict(self, msg_name_key=False,
                         asn_values=False):  # Establish ItsMessage object for every type of msg in config
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
            if 'ITS' in str(pkt.layers):
                if 'MALFORMED' in str(pkt.layers):
                    packet_array.append(f'Packet no. {idx + 1}: malformed packet')
                else:
                    try:
                        msg_object = msg_types.get(pkt.btpb.dstport)
                    except KeyError:
                        packet_array.append(
                            f'Packet no. {idx + 1}: unsupported C-ITS message type with dstport {pkt.btpb.dstport}.')
                    else:
                        pkt_decoded = msg_object.decode(bytes.fromhex(pkt.its_raw.value))
                        if isinstance(pkt_decoded, dict):
                            packet_array.append(pkt_decoded)
                        else:
                            packet_array.append(f'Packet no. {idx + 1}: {pkt_decoded}')
            else:
                packet_array.append(f'Packet no. {idx + 1}: Not a C-ITS packet.')
        return packet_array


def process_packet(packet: dict) -> dict:
    def process_list(input_list: list):
        output_dict = {}
        for index, item in enumerate(input_list):
            match item:
                case list():
                    output_dict[f'listItem{index}'] = process_list(item)
                case dict():
                    output_dict[f'listItem{index}'] = process_packet(item)
                case _:
                    output_dict[f'listItem{index}'] = item
        return output_dict

    output_dict = {}
    for key, value in packet.items():
        match value:
            case tuple():  # Convert CHOICE, BIT STRING
                match value[0]:
                    case str():  # CHOICE: (str, object), to {str: object}
                        output_dict[key] = process_packet({value[0]: value[1]})
                    case bytes():  # BIT STRING: (bytes, int) -> bitstring
                        binary_string = ''.join(format(byte, '08b') for byte in value[0])
                        binary = binary_string[:value[1]]
                        output_dict[key] = binary
            case list():  # list -> dict
                output_dict[key] = process_list(value)
            case dict():  # go one level deeper
                output_dict[key] = process_packet(value)
            case _:
                output_dict[key] = value
    return output_dict


def recursive_parameters(packet: dict, path=None):  # Generator used to iterate through every parameter of the packet
    if path is None:
        path = []
    for key, value in packet.items():
        match value:
            case dict():
                yield from recursive_parameters(value, path + [key])
            case list():
                for index, item in enumerate(value):
                    yield from recursive_parameters(item, path + [key] + [index])
            case _:
                yield path + [key], key, value