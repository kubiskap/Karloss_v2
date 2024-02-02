import asn1tools
import pyshark
import json
from plugins.msg import ItsMessage


def get_msg_types(config_location, get_port_numbers, check_constraints):
    with open(config_location, 'r') as f:
        config = json.loads(f.read())
    # Establish "ItsMessage" object for each msg_type in config
    msgTypes = {}
    for i in config['msgPorts']:
        if get_port_numbers:
            msgTypes[i] = ItsMessage(msg_type=config['msgPorts'][i]['msgName'],
                                     asn_file=config['msgPorts'][i]['asnFiles'],
                                     check_constraints=check_constraints)
        else:
            msgTypes[config['msgPorts'][i]['msgName']] = ItsMessage(msg_type=config['msgPorts'][i]['msgName'],
                                                                    asn_file=config['msgPorts'][i]['asnFiles'],
                                                                    check_constraints=check_constraints)
    return msgTypes


def get_packet_array(input_file,
                     config_file):  # Method to decode all packets in "input_file" and stack them into a list
    cap = pyshark.FileCapture(input_file, include_raw=True, use_json=True)
    pkts = []
    pktErrs = []
    noErr = []
    msgPorts = get_msg_types(config_location=config_file, get_port_numbers=True, check_constraints=True)
    msgNames = get_msg_types(config_location=config_file, get_port_numbers=False, check_constraints=True)
    iteration = -1
    for pkt in cap:
        iteration += 1
        func = msgPorts.get(pkt.btpb.dstport)
        decErr = {}
        conErr = {}
        try:
            pkt_decoded = func.decode(bytes.fromhex(pkt.its_raw.value))
            pkts.append(pkt_decoded)
        except asn1tools.DecodeError as de:
            decErr[str(de).split(': ')[0]] = str(de).split(': ')[1]
        except asn1tools.ConstraintsError as ce:
            conErr[str(ce).split(': ')[0]] = str(ce).split(': ')[1]
        finally:
            if not len(pkts) != iteration:
                pkts.append('Packet which was not decoded due to error')
            else:
                noErr.append(iteration)
            pktErrs.append([decErr, conErr])
    return pkts, pktErrs, noErr
