import pyshark
import asn1tools

ItsDictionary = asn1tools.parse_files("./asn/temp.asn")
ItsMsg = asn1tools.compile_dict(ItsDictionary, 'uper')
print(ItsDictionary)