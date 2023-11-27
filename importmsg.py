import io
import datetime
import asn1tools

class ItsMessage(object):
    def __init__(
            self,
            asnFile,
            encodingType='uper',
            checkConstraints=False,
            stationId=1,
            latitude=500834073,
            longitude=144165981,
            stationType=5
    ):
        self.GenerationTime = 0
        self.DeltaTime = 0
        self.StationId = stationId
        self.Latitude = latitude
        self.Longitude = longitude
        self.StationType = stationType
        self.ItsDictionary = asn1tools.parse_files(asnFile)
        self.checkConstraints = checkConstraints
        self.ItsMsg = asn1tools.compile_dict(self.ItsDictionary, encodingType)
    def getDictionary(self):
        return self.ItsDictionary


