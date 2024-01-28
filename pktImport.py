import pyshark
import json
from plugins import *
from plugins.msg import get_msg_types


def get_packet_array(input_file, config_file):  # Method to decode all packets in "input_file" and stack them into a list
    cap = pyshark.FileCapture(input_file, include_raw=True, use_json=True)
    pkts = []
    msgPorts = get_msg_types(config_location=config_file, get_port_numbers=True)
    msgNames = get_msg_types(config_location=config_file, get_port_numbers=False)
    for pkt in cap:
        func = msgPorts.get(pkt.btpb.dstport)
        pkt_decoded = func.decode(bytes.fromhex(pkt.its_raw.value))
        pkts.append(pkt_decoded)
    return pkts
