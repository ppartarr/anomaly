#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

# Check if cython code has been compiled
import platform
import os.path
from scapy.all import rdpcap, sys
from scapy.layers.inet import ICMP, UDP, TCP, IP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP
import numpy as np
import csv
import os
import subprocess

from anomaly.models.online.kitnet.stats.network import NetworkStatistics
from anomaly.readers.pcap import PCAPReader
from anomaly.readers.tsv import TSVReader
import logging as log

log = log.getLogger(__name__)

use_extrapolation = False  # experimental correlation code
if use_extrapolation:
    print("Importing AfterImage Cython Library")
    if not os.path.isfile("AfterImage.c"):  # has not yet been compiled, so try to do so...
        cmd = "python setup.py build_ext --inplace"
        subprocess.call(cmd, shell=True)


class RawPacketFeatureExtractor:
    """Extracts Kitsune features from given pcap file one packet at a time using "get_next_vector()"
    If wireshark is installed (tshark) it is used to parse (it's faster), otherwise, scapy is used (much slower).
    If wireshark is used then a tsv file (parsed version of the pcap) will be made -which you can use as your input next time"""

    def __init__(self, path, reader, limit=np.inf):
        self.path = path
        self.reader = reader(path, limit)
        self.limit = limit
        self.parse_type = None  # unknown

        # Prep Feature extractor (AfterImage)
        maxHost = 100000000000
        maxSess = 100000000000
        self.network_statistics = NetworkStatistics(np.nan, maxHost, maxSess)

    def get_num_features(self):
        # log.info(self.network_statistics.get_net_stat_headers())
        log.info('There are {num_headers} features'.format(
            num_headers=len(self.network_statistics.get_net_stat_headers())))
        return len(self.network_statistics.get_net_stat_headers())

    def get_next_vector(self):
        # Parse next packet
        if isinstance(self.reader, TSVReader):
            row = self.reader.get_next_row()
            if row == []:
                return []
            IPtype = np.nan
            timestamp = row[0]
            framelen = row[1]
            srcIP = ''
            dstIP = ''
            if row[4] != '':  # IPv4
                srcIP = row[4]
                dstIP = row[5]
                IPtype = 0
            elif row[17] != '':  # ipv6
                srcIP = row[17]
                dstIP = row[18]
                IPtype = 1
            srcproto = row[6] + row[
                8]  # UDP or TCP port: the concatenation of the two port strings will will results in an OR "[tcp|udp]"
            dstproto = row[7] + row[9]  # UDP or TCP port
            srcMAC = row[2]
            dstMAC = row[3]
            if srcproto == '':  # it's a L2/L1 level protocol
                if row[12] != '':  # is ARP
                    srcproto = 'arp'
                    dstproto = 'arp'
                    srcIP = row[14]  # src IP (ARP)
                    dstIP = row[16]  # dst IP (ARP)
                    IPtype = 0
                elif row[10] != '':  # is ICMP
                    srcproto = 'icmp'
                    dstproto = 'icmp'
                    IPtype = 0
                elif srcIP + srcproto + dstIP + dstproto == '':  # some other protocol
                    srcIP = row[2]  # src MAC
                    dstIP = row[3]  # dst MAC

        elif isinstance(self.reader, PCAPReader):
            packet = self.reader.get_next_row()
            if packet == []:
                return []
            IPtype = np.nan
            timestamp = packet.time
            framelen = len(packet)
            if packet.haslayer(IP):  # IPv4
                srcIP = packet[IP].src
                dstIP = packet[IP].dst
                IPtype = 0
            elif packet.haslayer(IPv6):  # ipv6
                srcIP = packet[IPv6].src
                dstIP = packet[IPv6].dst
                IPtype = 1
            else:
                srcIP = ''
                dstIP = ''

            if packet.haslayer(TCP):
                srcproto = str(packet[TCP].sport)
                dstproto = str(packet[TCP].dport)
            elif packet.haslayer(UDP):
                srcproto = str(packet[UDP].sport)
                dstproto = str(packet[UDP].dport)
            else:
                srcproto = ''
                dstproto = ''

            srcMAC = packet.src
            dstMAC = packet.dst
            if srcproto == '':  # it's a L2/L1 level protocol
                if packet.haslayer(ARP):  # is ARP
                    srcproto = 'arp'
                    dstproto = 'arp'
                    srcIP = packet[ARP].psrc  # src IP (ARP)
                    dstIP = packet[ARP].pdst  # dst IP (ARP)
                    IPtype = 0
                elif packet.haslayer(ICMP):  # is ICMP
                    srcproto = 'icmp'
                    dstproto = 'icmp'
                    IPtype = 0
                elif srcIP + srcproto + dstIP + dstproto == '':  # some other protocol
                    srcIP = packet.src  # src MAC
                    dstIP = packet.dst  # dst MAC
        else:
            return []

        # Extract Features
        try:
            return self.network_statistics.update_get_stats(IPtype, srcMAC, dstMAC, srcIP, srcproto, dstIP, dstproto,
                                                            int(framelen),
                                                            float(timestamp))
        except Exception as e:
            print(e)
            return []
