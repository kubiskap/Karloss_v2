from plugins import *
import pandas
from collections import ChainMap
from pktImport import get_packet_array
from plugins.msg import get_msg_types

def extract_asn_dict_types(asn_dict):
    dictList = []
    for i in asn_dict:
        dictList.append(pktDict[i]['types'])
    asn_dict_types = dict(ChainMap(*dictList))
    return asn_dict_types

packets = get_packet_array('./test.pcap', './config.json')
msgTypes = get_msg_types('./config.json', False)

dictMsgTypes = {}
for i in msgTypes:
    dictMsgTypes[i] = msgTypes[i].get_dictionary()

for pkt in packets:
    msgName = list(pkt.keys())[0].upper()
    pktDict = dictMsgTypes.get(msgName)
    types = extract_asn_dict_types(pktDict)
    for param in pkt[msgName]:
        dict = types[param]
        if dict['type'] == 'SEQUENCE': # if you find sequence, you need to go one level deeper in the dictionary
            for member in dict['type']['members']:
                # see if all members are there (the ones with parameter "optional"=True can be missing), if not, add error
        if dict['type'] == 'INTEGER':
            for named_number in dict['type']['named-numbers']:
                # check if value is in named numbers, if not, add warning
                # if yes, replace the number with the "named-number" value in original packet
            for restriction in dict['type']['restricted-to']:
                # check if value is within defined bounds, if not, add error
        if dict['type'] == 'ENUMERATED':
            for value in dict['type']['values']:
                # check if parameter equals to one of the exact values defined, if not, add error
        if dict['type'] == 'SEQUENCE OF':
                # idk have yet to check
        if dict['type'] == 'BIT STRING':
            for named_bit in dict['type']['named-bits']:
                # check if value corresponds with any named-bit, if not, add warning
            # also check size of bit, if not within defined size, add error
        if dict['type'] == 'BOOLEAN':
            # check if is boolean
        if dict['type'] == 'OCTET STRING':
            #
        if dict['type'] == 'CHOICE':
            # check if the value is one of the names defined in 'members'
        if dict['type'] == 'IA5String':
            # check size
        if dict['type'] == 'NumericString':
            # check size
        if dict['type'] == 'NumericString':
            # check size
        else:
            # the type is defined somewhere else in the document, look for it