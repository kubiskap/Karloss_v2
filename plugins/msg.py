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
        self.its_dictionary = asn1tools.parse_files(asn_file)
        self.check_constraints = check_constraints
        self.its_msg = asn1tools.compile_dict(self.its_dictionary, encoding_type)
        self.msg_type = msg_type
    def get_dictionary(self):  # vrati python slovnik, ktery vezme z asn souboru
        return self.its_dictionary

    def decode(self, encoded):  # dekodovani zpravy
        return self.its_msg.decode(self.msg_type, encoded, check_constraints=self.check_constraints)
