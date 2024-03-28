from pktImport import recursive_parameters
import copy
import jsonpath_ng


def summary_add_value(val_dict: dict, parameter: str, value_type: str) -> dict:
    """
    Function which adds value to a summary dictionary, depending on the parameter.
    If the parameter is not present in the dictionary, it creates it with default all-zeros values.
    The format is as follows:
     -- Each key is parameter name.
     -- Value of each key is a list of 3 integers, when created, they are all zeroes.
     -- First number represents a number of packets without Error.
     -- The second number represents a number of packets with Warning flag, optional parameter is missing,
        number not in named-numbers etc.
     -- The third parameter represents a number of packets with Error -- mandatory parameters missing, not valid data
        type etc.
    """
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
    """
    A class to distinguish problems with parameters.
    The flag parameter can be either 0 (problem which is then added to summary as 'Warning') and 1 ('Error').
    """

    def __init__(self, flag, desc):
        self.flag = flag
        self.desc = desc


def analyse_packet(packet: dict, asn_dictionary: dict, summary_dict=None) -> tuple[dict, dict[str, list]]:
    """
    Function that analyses each parameter of the packet. Takes data from generator "recursive_parameters" specified in
    "pktImport.py".
    Uses jsonpath_ng to retrieve parameter specification from asn_dictionary, which is created for each message type specified in a config.
    Then, depending on the type of parameter, checks if value is in named-numbers, checks if all mandatory parameters are present, etc.
    """
    if summary_dict is None:
        summary_dict = {}

    def convert_item_path(input_path: list) -> tuple[list, str]:
        """
        Sub-function that converts path containing any "listItem" keys. Determines type of item based on superior
        parameter and replaces each "listItem" with the parameter in specification of superior parameter (which should
        always be of type "SEQUENCE OF".

        Also converts path of the asn specification, which corresponds to asn_dictionary structure.
        """

        path_converted = input_path.copy()
        if any('listItem' in path_keys for path_keys in path_converted):
            asn_path = []
            for path_idx, path_item in enumerate(path_converted):
                if path_item.startswith('listItem') and not path_converted[path_idx - 1].startswith('listItem'):
                    asn_path.append('element')
                    matches_element = jsonpath_ng.parse("$." + ".".join(asn_path)).find(asn_dictionary)
                    path_converted[path_idx] = list(matches_element[0].value.keys())[0]
                asn_path.append(path_converted[path_idx])
        else:
            asn_path = path_converted.copy()
        return path_converted, asn_path

    packet_analysed = copy.deepcopy(packet)
    for path, key, value in recursive_parameters(packet_analysed):
        problems = []  # If a problem is detected with parameter, the details are added in this list.
        path_converted, asn_path = convert_item_path(path)
        asn_matches = jsonpath_ng.parse("$." + ".".join(asn_path)).find(asn_dictionary)
        if not asn_matches:
            # Parameter not found in ASN dictionary
            problems.append(Problem(1, 'ASN data type invalid or definition not found for this parameter.'))
            break
        else:
            asn = asn_matches[0].value
        if asn == 'ASN not found':
            # This means that the ASN decompiler could not find a definition for this parameter type.
            problems.append(Problem(1, 'ASN definition not found for this parameter.'))
        elif not isinstance(asn, dict):
            # In case "asn" is not dict, throw a TypeError.
            print(asn)
            raise TypeError(f'ASN not dict type for parameter located on "{path}"')
        # Generic errors and warnings (based on value type)
        elif 'type' in asn.keys():
            # Type key is found in all data types except "SEQUENCE" and "CHOICE".

            if asn['type'] == 'INTEGER':

                if 'restricted-to' in asn.keys():
                    in_range = []
                    for restriction in asn['restricted-to']:
                        if restriction is not None:
                            in_range.append(value in range(restriction[0], restriction[1] + 1))
                    if not all(in_range):
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
                                 list(asn['named-numbers'].keys())[
                                     list(asn['named-numbers'].values()).index(value)]]

            elif asn['type'] == 'ENUMERATED':
                if 'values' in asn.keys():
                    value_list = []

                    for i in asn['values']:
                        if isinstance(i, tuple):
                            value_list.append(i[0])
                        else:
                            value_list.append(i)
                    if value not in value_list:
                        problems.append(Problem(1, 'Value not in defined values.'))
                    elif value == 'unavailable':
                        problems.append(Problem(0, 'Value is unavailable.'))

            elif asn['type'] in ['IA5String', 'NumericString', 'SEQUENCE OF']:
                if 'size' in asn.keys():
                    size_allowed = []
                    for size in asn['size']:
                        if not None:
                            size_allowed.append(len(value) in range(size[0], size[1] + 1))
                        else:
                            size_allowed.append(value is None)
                    if not all(size_allowed):
                        problems.append(Problem(1, 'Out of specified size.'))

            elif asn['type'] == 'BIT STRING':
                if 'size' in asn.keys():
                    if len(value) != asn['size'][0]:
                        problems.append(Problem(1, 'Out of specified size.'))
                if 'named-bits' in asn.keys():
                    bits_activated = []
                    for index, bit in enumerate(list(value)):
                        if bit == '1':
                            bits_activated.append(asn['named-bits'][index][0])
                    value = [value, bits_activated]

# --- The asn1tools compiler should be doing this
#            elif asn['type'] == 'BOOLEAN':
#                if not isinstance(value, bool):
#                    problems.append(Problem(1, 'Not specified type.'))
#            elif asn['type'] == 'OCTET STRING':
#                if not isinstance(value, bytes):
#                    problems.append(Problem(1, 'Not specified type.'))

            elif asn['type'] == 'SEQUENCE OF':
                if 'size' in asn.keys():
                    size_allowed = []
                    for size in asn['size']:
                        if not None:
                            size_allowed.append(len(value.keys()) in range(size[0], size[1] + 1))
                        else:
                            size_allowed.append(value is None)
                    if not all(size_allowed):
                        problems.append(Problem(1, 'Out of specified size.'))

        elif 'member-type_type' in asn.keys():
            # "member-type_type" is found in only "SEQUENCE" and "CHOICE" parameter types. The reason for the different
            # naming of the key is because there might be a sub-parameter named "type", which would be
            # then subsequently overwritten by the key 'type': 'SEQUENCE'/'CHOICE'

            if asn['member-type_type'] == 'SEQUENCE':
                for member, memAsnValue in asn.items():
                    if isinstance(memAsnValue, dict) and member not in value.keys() and memAsnValue.get('optional') is not True:
                        problems.append(Problem(1, f'Mandatory parameter {member} missing.'))
                    elif isinstance(memAsnValue, dict) and member not in value.keys() and memAsnValue.get('optional') is True:
                        problems.append(Problem(0, f'Optional parameter {member} missing.'))

            elif asn['member-type_type'] == 'CHOICE':
                if list(value.keys())[0] not in asn.keys():
                    problems.append(Problem(1, f'Mandatory parameter {list(value.keys())[0]} missing.'))

        else:
            problems.append(Problem(1, 'Type not defined.'))
        # Message type-specific errors and warnings

        # .... TBD ....

        # Evaluation - problem objects are added into lists and then the value of parameter is overwritten by list of
        # [<parameter value>, <state of parameter - Error/Warning/OK>, <list of problem descriptions or
        # None if there are none present>].
        problem_flags, problem_descs = [], []
        for problem in problems:
            problem_flags.append(problem.flag)
            problem_descs.append(problem.desc)
        if 1 in problem_flags:
            parameter_state = 'Error'
        elif 0 in problem_flags:
            parameter_state = 'Warning'
        else:
            parameter_state = 'OK'

        summary_add_value(summary_dict, '.'.join(list(path_converted)), parameter_state)

        # Construct the value to be assigned
        value_to_set = [value, parameter_state, None if not problem_flags else problem_descs]

        matches = jsonpath_ng.parse("$." + ".".join(path)).find(packet_analysed)
        # Set the value directly using JSONPath
        matches[0].full_path.update(packet_analysed, value_to_set)
    return packet_analysed, summary_dict
