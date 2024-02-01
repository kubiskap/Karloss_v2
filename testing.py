from plugins import *
from collections import ChainMap
from pktImport import get_packet_array
from plugins.msg import get_msg_types

def extract_asn_all_parameters(asn_dict):
    dictList = []
    for i in asn_dict:
        dictList.append(pktDict[i]['types'])
    asn_dict_types = dict(ChainMap(*dictList))
    temp = {}
    typesNamesDict = {}
    for parType in asn_dict_types:
        if 'members' in list(asn_dict_types[parType].keys()):
            for member in asn_dict_types[parType]['members']:
                if member is None:
                    break
                if member['type'] in ['INTEGER', 'SEQUENCE', 'ENUMERATED', 'BIT STRING', 'BOOLEAN', 'OCTET STRING', 'CHOICE', 'IA5String', 'NumericString']:
                    temp[member['name']] = member
                else:
                    typesNamesDict[member['name']] = member['type']
            asn_dict_types = asn_dict_types | temp
    return asn_dict_types, typesNamesDict


def summary_add_value(val_dict, parameter, value):
    if parameter in val_dict:
        if value == 'Error':
            val_dict[parameter][2] += 1
        if value == 'Warning':
            val_dict[parameter][1] += 1
        if value == 'OK':
            val_dict[parameter][0] += 1
    else:
        val_dict[parameter] = [0, 0, 0]  # OK, Error, Warning
        summary_add_value(val_dict, parameter, value)
    return val_dict


def recursive_msg_parameters(packet):
    for key, value in packet.items():
        if type(value) is dict:
            yield from recursive_msg_parameters(value)
        if type(value) is tuple:
            yield (key, value)
        if type(value) is tuple and type(value[0]) is str and type(value[1]) is dict:
            yield from recursive_msg_parameters(value[1])
        else:
            yield (key, value)


packets = get_packet_array('./test_kapsch_consignia.pcap', './config.json')
msgTypes = get_msg_types('./config.json', False)

dictMsgTypes = {}
for i in msgTypes:
    dictMsgTypes[i] = msgTypes[i].get_dictionary()


summary = {}
pktsAnalysed = []


for pkt in packets:
    msgName = list(pkt.keys())[0].upper()
    pktDict = dictMsgTypes.get(msgName)
    types, typeNames = extract_asn_all_parameters(pktDict)
    paramsAnalysed = {}
    for key, value in recursive_msg_parameters(pkt):
        problem = {}
        if key in types.keys():
            asn = types.get(key)
        else:
            asn = types.get(typeNames.get(key))
    # Generic errors and warnings (based on value type)
        if asn['type'] == 'INTEGER':
            if not isinstance(value, int):
                problem[1] = 'Not specified type.'
            if 'restricted-to' in asn.keys():
                inRange = []
                for restriction in asn['restricted-to']:
                    inRange.append(value in range(restriction[0], restriction[1] + 1))
                if not all(inRange):
                    problem[1] = 'Out of range.'
            if 'named-numbers' in asn.keys():
                if value not in asn['named-numbers'].values():
                    problem[0] = 'Value not in named-numbers.'
                else:
                    value = [value, list(asn['named-numbers'].keys())[list(asn['named-numbers'].values()).index(value)]]
        if asn['type'] == 'ENUMERATED':
            if not isinstance(value, str):
                problem[1] = 'Not specified type.'
            if 'values' in asn.keys():
                valueList = []
                for i in asn['values']:
                    if isinstance(i, tuple):
                        valueList.append(i[0])
                    else:
                        valueList.append(i)
                if value not in valueList:
                    problem[1] = 'Value not in defined values.'
        if asn['type'] == 'SEQUENCE OF':
            if not isinstance(value, tuple):
                problem[1] = 'Not specified type.'
            if 'size' in asn.keys():
                sizeAllowed = []
                for size in asn['size']:
                    if not None:
                        sizeAllowed.append(len(value) in range(size[0], size[1] + 1))
                    else:
                        sizeAllowed.append(value is None)
                if not all(sizeAllowed):
                    problem[1] = 'Out of specified size.'
        if asn['type'] in ['IA5String','NumericString']:
            if not isinstance(value, str):
                problem[1] = 'Not specified type.'
            if 'size' in asn.keys():
                sizeAllowed = []
                for size in asn['size']:
                    if isinstance(size, dict):
                        sizeAllowed.append(len(value) in range(size[0], size[1] + 1))
                    if isinstance(size, int):
                        sizeAllowed.append(value == size)
                if not all(sizeAllowed):
                    problem[1] = 'Out of specified size.'
        if asn['type'] == 'BIT STRING':
            if not isinstance(value, tuple):
                problem[1] = 'Not specified type.'
            if 'size' in asn.keys():
                sizeAllowed = []
                for size in asn['size']:
                    if isinstance(size, dict):
                        sizeAllowed.append(len(value) in range(size[0], size[1] + 1))
                    if isinstance(size, int):
                        sizeAllowed.append(value == size)
                if not all(sizeAllowed):
                    problem[1] = 'Out of specified size.'
            if 'named-bits' in asn.keys():
                for named_bit in asn['named-bits']:
                    pass
        if asn['type'] == 'BOOLEAN':
            if not isinstance(value, bool):
                problem[1] = 'Not specified type.'
        if asn['type'] == 'OCTET STRING':
            if not isinstance(value, bytes):
                problem[1] = 'Not specified type.'
        if asn['type'] == 'CHOICE':
            if not isinstance(value, tuple):
                problem[1] = 'Not specified type.'
            if 'members' in asn.keys():
                for member in asn['members']:
                    pass

    # Message type-specific errors and warnings

        if 1 in problem.keys():
            state = 'Error'
        elif 0 in problem.keys() and 1 not in problem.keys():
            state = 'Warning'
        else:
            state = 'OK'
        summary_add_value(summary, key, state)
        paramsAnalysed[key] = [value, state, None if not list(problem.values()) else list(problem.values())]
    pktsAnalysed.append(paramsAnalysed)










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