# Karloss_v2 main

# Imports
import asn1tools
import json

its_dictionary_dir = asn1tools.parse_files([
    "./asn/vanetza/TS102894-2v131-CDD.asn",
    "./asn/vanetza/EN302637-2v141-CAM.asn",
    "./asn/vanetza/ISO14816.asn",
    "./asn/vanetza/ISO19091.asn",
    "./asn/vanetza/ISO24534-3.asn",
    "./asn/vanetza/TR103562v211-CPM.asn",
    "./asn/vanetza/TS103301v211-MAPEM.asn"])

with open('its_map_before.json', 'w') as json_file:
    json.dump(its_dictionary_dir, json_file, indent=2)

its_msg = asn1tools.compile_dict(its_dictionary_dir, 'uper')

with open('its_map_after.json', 'w') as json_file:
    json.dump(its_dictionary_dir, json_file, indent=2)