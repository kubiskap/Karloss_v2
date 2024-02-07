from pktImport import Packets
from pktImport import recursive_parameters
from pktImport import deal_with_choice_type
from collections import ChainMap
import dpath
import datetime
import copy


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


class Problem(object):
    def __init__(self, flag, desc):
        self.flag = flag
        self.desc = desc


def get_dictionary_all_parameters(asn_dict):
    dict_list = []
    for container in asn_dict:
        dict_list.append(asn_dict[container]['types'])
    asn_dict_types = dict(ChainMap(*dict_list))
    temp = {}
    type_names_dict = {}
    for par_type in asn_dict_types:
        if 'members' in list(asn_dict_types[par_type].keys()):
            for par_member in asn_dict_types[par_type]['members']:
                if par_member is None:
                    break
                if par_member['type'] in ['INTEGER', 'SEQUENCE', 'ENUMERATED', 'BIT STRING', 'BOOLEAN', 'OCTET STRING',
                                          'CHOICE', 'IA5String', 'NumericString']:
                    temp[par_member['name']] = par_member
                else:
                    type_names_dict[par_member['name']] = par_member['type']
            asn_dict_types = asn_dict_types | temp
    return asn_dict_types, type_names_dict


time_start = datetime.datetime.now()
summary = {}
pktsAnalysed = []

pktClass = Packets(input_file='./pcap/test4.pcap')
packets = pktClass.get_packet_array()

msgDicts = {}
for msgType in pktClass.get_msg_types().values():
    msgDicts[msgType[1]] = msgType[0].get_dictionary()

for pkt in packets:
    if not isinstance(pkt, dict):
        pktsAnalysed.append(pkt)
    else:
        paramsAnalysed = {}
        pktAnalysed = deal_with_choice_type(pkt)
        msgName = list(pkt.keys())[0].upper()
        pktDict = msgDicts.get(msgName)
        types, typeNames = get_dictionary_all_parameters(pktDict)
        for path, key, value in recursive_parameters(pktAnalysed):
            problems = []
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
                        problems.append(Problem(1, 'Out of range.'))
                if 'named-numbers' in asn.keys():
                    try:
                        if value == asn['named-numbers']['unavailable']:
                            problems.append(Problem(0, 'Value is unavailable.'))
                    except KeyError:
                        pass
                    if value not in asn['named-numbers'].values():
                        problems.append(Problem(0, 'Value not in named-numbers.'))
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
                        problems.append(Problem(1, 'Value not in defined values.'))
                    elif value == 'unavailable':
                        problems.append(Problem(1, 'Value is unavailable.'))
            if asn['type'] in ['IA5String', 'NumericString', 'SEQUENCE OF']:
                if 'size' in asn.keys():
                    sizeAllowed = []
                    for size in asn['size']:
                        if not None:
                            sizeAllowed.append(len(value) in range(size[0], size[1] + 1))
                        else:
                            sizeAllowed.append(value is None)
                    if not all(sizeAllowed):
                        problems.append(Problem(1, 'Out of specified size.'))
            if asn['type'] == 'BIT STRING':
                if 'size' in asn.keys():
                    if value[1] != asn['size'][0]:
                        problems.append(Problem(1, 'Out of specified size.'))
                if 'named-bits' in asn.keys():
                    for named_bit in asn['named-bits']:
                        pass
            if asn['type'] == 'BOOLEAN':
                if not isinstance(value, bool):
                    problems.append(Problem(1, 'Not specified type.'))
            if asn['type'] == 'OCTET STRING':
                if not isinstance(value, bytes):
                    problems.append(Problem(1, 'Not specified type.'))
            if asn['type'] == 'CHOICE':
                if 'members' in asn.keys():
                    choiceBool = []
                    for chMember in asn['members']:
                        if chMember is not None:
                            choiceBool.append(chMember['name'] in value.keys())
                    if not any(choiceBool):
                        problems.append(Problem(1, 'Value not in defined values.'))
                dpath.set(pktAnalysed, path, value)
            if asn['type'] == 'SEQUENCE':
                if 'members' in asn.keys():
                    for seqMember in asn['members']:
                        if seqMember is not None and seqMember['name'] not in value.keys() and seqMember.get(
                                'optional') is not True:
                            problems.append(Problem(1, f'Mandatory parameter {seqMember['name']} missing.'))
                        if seqMember is not None and seqMember['name'] not in value.keys():
                            problems.append(Problem(0, f'Optional parameter {seqMember['name']} missing.'))
            # Message type-specific errors and warnings

            # .... TBD ....

            problemFlags, problemDescs = [], []
            for problem in problems:
                problemFlags.append(problem.flag)
                problemDescs.append(problem.desc)
            if 1 in problemFlags:
                state = 'Error'
            elif 0 in problemFlags:
                state = 'Warning'
            else:
                state = 'OK'
            summary_add_value(summary, '/'.join(path), state)
            dpath.set(pktAnalysed, path, [value, state, None if not problemDescs else problemDescs])
        pktsAnalysed.append(pktAnalysed)

time_end = datetime.datetime.now()
