import pyshark
from plugins.msg import ItsMessage

cap = pyshark.FileCapture('./test_kapsch_consignia.pcap',include_raw=True,use_json=True)
CAM = ItsMessage(asn_file=['./asn/en/v1/ITSv1-Container.asn','./asn/en/v1/CAMv1-PDU-Descriptions.asn'],msg_type='CAM',encoding_type='uper')

packet = cap[5423]
pkt_decoded = CAM.decode(bytes.fromhex(packet.its_raw.value))
