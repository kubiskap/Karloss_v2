from plugins.msg import ItsMessage


class DenmMessage(ItsMessage):
    """
    ETSI CAM message
    """

    def __init__(
            self,
            asn_file,
            encoding_type='uper',
            check_constraints=False,
    ):
        self.msg_type = 'DENM'
        super().__init__(asn_file, encoding_type, check_constraints)

    def decode(self, encoded):
        return self.its_msg.decode('DENM', encoded, check_constraints=self.check_constraints)
