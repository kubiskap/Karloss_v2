import asn1tools


class ItsMessage(object):
    """
    ETSI ITS message
    """
    def __init__(
            self,
            asn_files,
            msg_type,
    ):
        self.its_dictionary = asn1tools.parse_files(asn_files)
        self.msg_type = msg_type

    def decode(self, encoded, encoding_type='uper'):  # dekodovani paketu
        compiled_dict = asn1tools.compile_dict(self.its_dictionary, encoding_type)
        try:
            decoded = compiled_dict.decode(self.msg_type, encoded, check_constraints=False)
        except asn1tools.DecodeError as error:
            print(error)
            decoded = {}
        except asn1tools.ConstraintsError as error:
            print(error)
            decoded = {}
        return {self.msg_name: decoded}
