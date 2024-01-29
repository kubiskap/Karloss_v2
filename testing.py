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


def recursive_msg_parameters(packet):
    for key, value in packet.items():
        if type(value) is dict:
            yield from recursive_msg_parameters(value)
        if type(value) is tuple and type(value[1]) is dict and type(value[0]) is str:
            yield from recursive_msg_parameters(value[1])
        else:
            yield (key, value)


packets = get_packet_array('./test.pcap', './config.json')
msgTypes = get_msg_types('./config.json', False)

dictMsgTypes = {}
for i in msgTypes:
    dictMsgTypes[i] = msgTypes[i].get_dictionary()

pkt = packets[0]
msgName = list(pkt.keys())[0].upper()
pktDict = dictMsgTypes.get(msgName)
types = extract_asn_dict_types(pktDict)
msgParams = {}
typesNamesDict = {}

for param in types:
    if 'members' in param.keys():
        for member in param['members']:
            types[member['name']] = member.values()

    #     dict = types[param]
    #     if type(param) is dict:
    #     if dict['type'] in ['SEQUENCE', 'CHOICE']:
    #         for member in dict['type']['members']:
    #             # see if all members are there (the ones with parameter "optional"=True can be missing), if not, add error
    #             if member['type'] in ['SEQUENCE', 'INTEGER', 'ENUMERATED']
    #
    #             else:
    #                 typesNamesDict[member['name']] = member['type']  #
    #
    #     if dict['type'] == 'INTEGER':
    #         for named_number in dict['type']['named-numbers']:
    #             # check if value is in named numbers, if not, add warning
    #             # if yes, replace the number with the "named-number" value in original packet
    #         for restriction in dict['type']['restricted-to']:
    #             # check if value is within defined bounds, if not, add error
    #     if dict['type'] == 'ENUMERATED':
    #         for value in dict['type']['values']:
    #             # check if parameter equals to one of the exact values defined, if not, add error
    #     if dict['type'] == 'SEQUENCE OF':
    #             # idk have yet to check
    #     if dict['type'] == 'BIT STRING':
    #         for named_bit in dict['type']['named-bits']:
    #             # check if value corresponds with any named-bit, if not, add warning
    #         # also check size of bit, if not within defined size, add error
    #     if dict['type'] == 'BOOLEAN':
    #         # check if is boolean
    #     if dict['type'] == 'OCTET STRING':
    #         #
    #     if dict['type'] == 'CHOICE':
    #         # check if the value is one of the names defined in 'members'
    #     if dict['type'] == 'IA5String':
    #         # check size
    #     if dict['type'] == 'NumericString':
    #         # check size
    #     if dict['type'] == 'NumericString':
    #         # check size
    #     else:
    #         # the type is defined somewhere else in the document, look for it