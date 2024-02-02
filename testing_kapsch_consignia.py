import pyshark
from plugins.msg import ItsMessage

cap = pyshark.FileCapture('./test_kapsch_consignia.pcap',include_raw=True,use_json=True)
CAM = ItsMessage(asn_file=['./asn/ETSI-ITS-CDD.asn','./asn/CAM_ts103900.asn'],msg_type='CAM',encoding_type='uper')

packet = cap[5423]
pkt_decoded = CAM.decode(bytes.fromhex(packet.its_raw.value))
