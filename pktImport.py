import pyshark
import json
from msg import ItsMessage


class Packets(object):
    """
    A class used to read packets from the pcap file and decode them into a pythonic array.

    """
    def __init__(self,
                 input_file,
                 config_location):
        self.input_file = input_file
        self.pcap = pyshark.FileCapture(self.input_file, include_raw=True, use_json=True)
        self.config_location = config_location
        with open(self.config_location, 'r') as f:
            self.config = json.loads(f.read())

    def get_its_msg_dict(self, msg_name_key=False, asn_values=False):
        """
        Method which establishes a dictionary, where keys are message ports or message names (msg_name_key=True)
        and values are ItsMessage objects or decoded ASN dictionaries (asn_values=True) of each message type.
        """
        configured_msgs = {}
        for msg_port, config_value in self.config['msgPorts'].items():
            dict_key = config_value['msgName'] if msg_name_key else msg_port
            its_message_object = ItsMessage(asn_files=config_value['asnFiles'], msg_name=config_value['msgName'])
            configured_msgs[dict_key] = its_message_object.asn_rebuilt if asn_values else its_message_object
        return configured_msgs

    def get_packet_array(self):
        """
        Method to decode all packets in "input_file" and stack them into a list of dictionaries.

        It recognizes if a packet is malformed or is not an ITS packet and adds this information into the list.
        """
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
                packet_array.append(f'Packet no. {idx+1}: Not a C-ITS packet.')
        return packet_array


def process_packet(input_dict):
    """
    A function to convert the decoded packet into a true dictionary.
    """
    def process_list(input_list):
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

    output_dict = {} # Establishes output
    for key, value in input_dict.items():

        # Convert CHOICE, which returns (str, value) into {str: value}
        if isinstance(value, tuple) and isinstance(value[0], str):
            output_dict[key] = process_packet({value[0]: value[1]})

        # Convert BIT STRING, which returns (bytes, int) to bits
        elif isinstance(value, tuple) and isinstance(value[0], bytes) and isinstance(value[1], int):
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


def recursive_parameters(packet, path=None):
    """
    Generator used to iterate through every parameter of the packet in "analyse_packet" function.
    """
    if path is None:
        path = []
    for key, value in packet.items():
        if isinstance(value, dict):
            yield from recursive_parameters(value, path + [key])
        elif isinstance(value, list):
            for index, item in enumerate(value):
                yield from recursive_parameters(item, path + [key] + [index])
        yield path + [key], key, value