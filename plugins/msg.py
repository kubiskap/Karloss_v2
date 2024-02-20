import asn1tools

class ItsMessage(object):
    """
    ETSI ITS message
    """
    def __init__(
            self,
            asn_file,
            msg_type,
            encoding_type='uper',
            check_constraints=False,
    ):
        self.decoded = None
        self.its_dictionary = asn1tools.parse_files(asn_file)
        self.check_constraints = check_constraints
        self.its_msg = asn1tools.compile_dict(self.its_dictionary, encoding_type)
        self.msg_type = msg_type

    def decode(self, encoded):  # dekodovani paketu
        try:
            decoded = self.its_msg.decode(self.msg_type, encoded, check_constraints=self.check_constraints)
        except asn1tools.DecodeError as error:
            print(error)
            decoded = {}
        except asn1tools.ConstraintsError as error:
            print(error)
            decoded = {}
        return {self.msg_type: decoded}
