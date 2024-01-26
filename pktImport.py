import pyshark
import json
import os
from plugins import *


class Analysis(object):
    def __init__(self,
                 input_file,
                 config_location
                 ):
        self.pkt_decoded = None
        self.func = None
        self.pkts = None
        self.cap = None
        self.value = None
        self.input_file = input_file  # Wireshark file with packets
        # Read configfile
        with open(config_location, 'r') as f:
            config = json.loads(f.read())
        # Establish "ItsMessage" object for each msg_type in config
        self.msgPorts = {}
        for i in config['msgPorts']:
            self.msgPorts[i] = ItsMessage(msg_type=config['msgPorts'][i]['msgName'],
                                     asn_file=config['msgPorts'][i]['asnFiles'])
    def fetch_pkts(self):  # Method to decode all packets in "input_file" and stack them into a list
        self.cap = pyshark.FileCapture(self.input_file, include_raw=True, use_json=True)
        self.pkts = []
        for pkt in self.cap:
            self.func = self.msgPorts.get(pkt.btpb.dstport)
            self.pkt_decoded = self.func.decode(bytes.fromhex(pkt.its_raw.value))
            self.pkts.append(self.pkt_decoded)
        return self.pkts

    def find_errors(self, pkts):
        for i in pkts:
            print('test')


analyse = Analysis('./test.pcap', './config.json')
packets = analyse.fetch_pkts()
