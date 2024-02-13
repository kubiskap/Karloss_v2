from pktImport import Packets
from pktImport import recursive_parameters
from pktImport import process_packet
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


def get_item_type_path(parameter_path, types_dictionary, type_names_dictionary):
    if any('listItem' in path_keys for path_keys in parameter_path):
        path_item_type_names = parameter_path.copy()
        for index, path_item in enumerate(parameter_path):
            if path_item[0:8] == 'listItem' and path_item_type_names[index-1][0:4] != 'listItem':
                if path_item_type_names[index-1] in types_dictionary.keys():
                    path_item_type_names[index] = types_dictionary.get(path_item_type_names[index-1])['element']['type']
                else:
                    path_item_type_names[index] = types_dictionary.get(type_names_dictionary.get(path_item_type_names[index-1]))['element']['type']
        return path_item_type_names
    else:
        return parameter_path


def get_asn_value_for_parameter(parameter_name, parameter_path, types_dictionary, type_names_dictionary):
    path_item = get_item_type_path(parameter_path, types_dictionary, type_names_dictionary)
    if parameter_name in types_dictionary.keys():
        asn = types_dictionary.get(parameter_name)
    elif parameter_name[0:8] == 'listItem':
            asn = types_dictionary.get(path_item[-1])
    else:
#        for type_names_key, type_names_value in type_names_dictionary:
#            if type_names_value == parameter_name:
        asn = types_dictionary.get(type_names_dictionary.get(parameter_name))
    return asn, path_item


def analyse_packet(pkt, summary, msg_dicts):
    if not isinstance(pkt, dict):
        return pkt
    else:
        packet_analysed = process_packet(pkt)
        msg_name = list(pkt.keys())[0].upper()
        packet_dict = msg_dicts.get(msg_name)
        types, type_names = get_dictionary_all_parameters(packet_dict)
        for path, key, value in recursive_parameters(packet_analysed):
            problems = []
            asn, path_item_types = get_asn_value_for_parameter(key, path, types, type_names)
            # Generic errors and warnings (based on value type)
            if asn['type'] == 'INTEGER':
                if 'restricted-to' in asn.keys():
                    inRange = []
                    for restriction in asn['restricted-to']:
                        if restriction is not None:
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
                    if len(value) != asn['size'][0]:
                        problems.append(Problem(1, 'Out of specified size.'))
                if 'named-bits' in asn.keys():
                    bits_activated = []
                    for index, bit in enumerate(list(value)):
                        if bit == '1':
                            bits_activated.append(asn['named-bits'][index][0])
                    value = [value, bits_activated]
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
            if asn['type'] == 'SEQUENCE OF':
                if 'size' in asn.keys():
                    sizeAllowed = []
                    for size in asn['size']:
                        if not None:
                            sizeAllowed.append(len(value.keys()) in range(size[0], size[1] + 1))
                        else:
                            sizeAllowed.append(value is None)
                    if not all(sizeAllowed):
                        problems.append(Problem(1, 'Out of specified size.'))

            # Message type-specific errors and warnings

            # .... TBD ....

            problem_flags, problem_descs = [], []
            for problem in problems:
                problem_flags.append(problem.flag)
                problem_descs.append(problem.desc)
            if 1 in problem_flags:
                state = 'Error'
            elif 0 in problem_flags:
                state = 'Warning'
            else:
                state = 'OK'
            summary_add_value(summary, '/'.join(list(map(str, path_item_types))), state)
            dpath.set(packet_analysed, path, [value, state, None if not problem_flags else problem_descs])
        return packet_analysed, summary




summary = {}
pktsAnalysed = []

pktClass = Packets(input_file='./pcap/test.pcap')
packets = pktClass.get_packet_array()

msgDicts = {}
for msgType in pktClass.get_msg_types().values():
    msgDicts[msgType[1]] = msgType[0].get_dictionary()

pktAnalysed, summary = analyse_packet(packets[7], summary, msgDicts)
