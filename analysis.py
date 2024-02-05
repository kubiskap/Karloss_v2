from pktImport import Packets
from pktImport import recursive_parameters
from collections import ChainMap
import dpath
import datetime


def summary_add_value(val_dict, parameter, value_type):
    if parameter in val_dict:
        if value_type == 'Error':
            val_dict[parameter][2] += 1
        if value_type == 'Warning':
            val_dict[parameter][1] += 1
        if value_type == 'OK':
            val_dict[parameter][0] += 1
    else:
        val_dict[parameter] = [0, 0, 0]  # OK, Error, Warning
        summary_add_value(val_dict, parameter, value_type)
    return val_dict


def get_dictionary_all_parameters(asn_dict):
    dictList = []
    for container in asn_dict:
        dictList.append(asn_dict[container]['types'])
    asn_dict_types = dict(ChainMap(*dictList))
    temp = {}
    typesNamesDict = {}
    for parType in asn_dict_types:
        if 'members' in list(asn_dict_types[parType].keys()):
            for member in asn_dict_types[parType]['members']:
                if member is None:
                    break
                if member['type'] in ['INTEGER', 'SEQUENCE', 'ENUMERATED', 'BIT STRING', 'BOOLEAN', 'OCTET STRING',
                                      'CHOICE', 'IA5String', 'NumericString']:
                    temp[member['name']] = member
                else:
                    typesNamesDict[member['name']] = member['type']
            asn_dict_types = asn_dict_types | temp
    return asn_dict_types, typesNamesDict


time_start = datetime.datetime.now()
summary = {}
pktsAnalysed = []

pktClass = Packets(input_file='./test_kapsch_consignia.pcap')
packets = pktClass.get_packet_array()

msgDicts = {}
for msgType in pktClass.get_msg_types().values():
    msgDicts[msgType[1]] = msgType[0].get_dictionary()

for pkt in packets:
    if not isinstance(pkt, dict):
        pktsAnalysed.append(pkt)
    else:
        #pktAnalysed = pkt
        paramsAnalysed = {}
        msgName = list(pkt.keys())[0].upper()
        pktDict = msgDicts.get(msgName)
        types, typeNames = get_dictionary_all_parameters(pktDict)
        paramsAnalysed = {}
        for path, key, value, in recursive_parameters(pkt):
            problem = {}
            if key in types.keys():
                asn = types.get(key)
            else:
                asn = types.get(typeNames.get(key))
            # Generic errors and warnings (based on value type)
            if asn['type'] == 'INTEGER':
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
                        value = [value,
                                 list(asn['named-numbers'].keys())[list(asn['named-numbers'].values()).index(value)]]
            if asn['type'] == 'ENUMERATED':
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
                if 'size' in asn.keys():
                    sizeAllowed = []
                    for size in asn['size']:
                        if not None:
                            sizeAllowed.append(len(value) in range(size[0], size[1] + 1))
                        else:
                            sizeAllowed.append(value is None)
                    if not all(sizeAllowed):
                        problem[1] = 'Out of specified size.'
            if asn['type'] in ['IA5String', 'NumericString']:
                if 'size' in asn.keys():
                    sizeAllowed = []
                    for size in asn['size']:
                        if not None:
                            sizeAllowed.append(len(value) in range(size[0], size[1] + 1))
                        else:
                            sizeAllowed.append(value is None)
                    if not all(sizeAllowed):
                        problem[1] = 'Out of specified size.'
            if asn['type'] == 'BIT STRING':
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
            #dpath.set(pktAnalysed, path, [value, state, None if not list(problem.values()) else list(problem.values())])
        pktsAnalysed.append(paramsAnalysed)

time_end = datetime.datetime.now()