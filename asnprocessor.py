from collections import ChainMap
import dpath
import copy

class AsnDictProcessor(object):
    def __init__(self, asn_dict, msg_name):
        self.asn_dict = asn_dict
        self.msg_name = msg_name
        self.types = dict(ChainMap(*[self.asn_dict[container]['types'] for container in self.asn_dict]))
        self.object_classes = dict(ChainMap(*[self.asn_dict[container]['object-classes'] for container in self.asn_dict]))
        self.rebuilt_asn = self.rebuild_asn(msg_name)

    def rebuild_asn(self, parameter_name, parameter_path=[]):
        parameter_asn = self.types.get(parameter_name)
        key_name = parameter_path[-1] if parameter_path else parameter_name
        output_dict = {}

        if parameter_asn is None:
            output_dict[key_name] = 'ASN not found'
        elif parameter_asn['type'] in self.types:
            output_dict[key_name] = self.process_type(parameter_asn, parameter_path + [key_name])
        elif parameter_asn['type'].split('.')[0] in self.object_classes:
            output_dict[key_name] = self.process_object_class(parameter_asn, parameter_path + [key_name])
        elif parameter_asn['type'] in ['SEQUENCE', 'CHOICE']:
            output_dict[key_name] = self.process_members(parameter_asn, parameter_path + [key_name])
        elif parameter_asn['type'] == 'SEQUENCE OF':
            output_dict[key_name] = self.process_sequence_of(parameter_asn, parameter_path + [key_name])
        else:
            output_dict[key_name] = parameter_asn

        return output_dict

    def process_members(self, input_dict, path):
        members_dict = {}
        for value in input_dict.get('members'):
            if value is None:
                break
            elif value['type'] in self.types:
                members_dict[value['name']] = self.process_type(value, path + [value['name']]) | {key: value for key, value in value.items() if key not in ['type', 'name']}
            elif value['type'].split('.')[0] in self.object_classes:
                members_dict[value['name']] = self.process_object_class(value, path + [value['name']])
            elif value['type'] in ['SEQUENCE', 'CHOICE']:
                members_dict[value['name']] = self.process_members(value, path + [value['name']]) | {key: value for key, value in value.items() if key not in ['type', 'name']}
            elif value['type'] == 'SEQUENCE OF':
                members_dict[value['name']] = self.process_sequence_of(value, path) | {key: value for key, value in value.items() if key not in ['type', 'element', 'name']}
            else:
                members_dict[value['name']] = value
        return members_dict | {'member-type_type': input_dict['type']}

    def process_object_class(self, value, path):
        object_class_type = value['type'].split('.')
        for object_class_member in self.object_classes.get(object_class_type[0])['members']:
            if object_class_member['name'] == object_class_type[1]:
                return list(self.rebuild_asn(object_class_member['type'], path).values())[0]

    def process_type(self, value, path):
        return list(self.rebuild_asn(value['type'], path).values())[0]

    def process_sequence_of(self, value, path):
        try:
            element_asn = self.rebuild_asn(value['element']['type'], path + [value['element']['type']])
        except KeyError:
            element_asn = self.rebuild_asn(list(value['element'])[0], path + [list(value['element'])[0]])
        value['element'] = element_asn
        return value


