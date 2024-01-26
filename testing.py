import pyshark
import asn1tools
import json
from plugins import *

cap = pyshark.FileCapture('./test.pcap', include_raw=True, use_json=True)

with open('./config.json', 'r') as f:
    config = json.loads(f.read())

msgPorts = {}
for i in config['msgPorts']:
    msgPorts[i] = ItsMessage(msg_type=config['msgPorts'][i]['msgName'], asn_file=config['msgPorts'][i]['asnFiles'])

pkts = []
for pkt in cap:
    func = msgPorts.get(pkt.btpb.dstport)
    binary = bytes.fromhex(pkt.its_raw.value)
    pkt_decoded = func.decode(binary)
    pkts.append(pkt_decoded)