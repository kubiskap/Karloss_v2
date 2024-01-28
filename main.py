# Karloss_v2 main

# Imports
from plugins import *
from pktImport import Analysis


def main():
    analyse = Analysis('./test.pcap', './config.json')
    packets = analyse.fetch_pkts()
if __name__ == '__main__':
    main()