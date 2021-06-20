#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

import logging as log
import numpy as np

from anomaly.extractors.protocols import convert_protocol_name_to_number
from anomaly.models.online.kitnet.stats.connection import ConnectionStatistics
from anomaly.utils import mac_to_decimal, ipv4_to_decimal, ipv6_to_decimal, convert_ip_address_to_decimal


class TLSClientHelloFeatureExtractor:
    def __init__(self, path, reader, limit=np.inf, encoded=False):
        self.path = path
        self.reader = reader(path, limit)
        self.limit = limit
        self.encoded = encoded

        # Prep feature extractor
        # max_hosts = 100000000000
        # max_sessions = 100000000000

        # self.connection_statistics = ConnectionStatistics(np.nan, max_hosts, max_sessions)

    def get_num_features(self):
        num_features = 25

        log.info('There are {num_headers} features'.format(num_headers=num_features))
        return num_features

    def get_next_vector(self):
        row = self.reader.get_next_row()
        if row == []:
            return []

        tls_client_hello = {
            'Timestamp': row[0],
            'Type': row[1],
            'Version': row[2],
            'MessageLen': row[3],
            'HandshakeType': row[4],
            'HandshakeLen': row[5],
            'HandshakeVersion': row[6],
            'SessionIDLen': row[7],
            'CipherSuiteLen': row[8],
            'ExtensionLen': row[9],
            'SNI': row[10],
            'OSCP': row[11],
            'CipherSuites': row[12],
            'CompressMethods': row[13],
            'SignatureAlgs': row[14],
            'SupportedGroups': row[15],
            'SupportedPoints': row[16],
            'ALPNs': row[17],
            'Ja3': row[18],
            'SrcIP': row[19],
            'DstIP': row[20],
            'SrcMAC': row[21],
            'DstMAC': row[22],
            'SrcPort': row[23],
            'DstPort': row[24],
        }

        # if not self.encoded:
        #     # Parse next packet
        #     try:
        #         connection = Connection(**conn)
        #         return self.connection_statistics.update_get_stats(connection)
        #     except Exception as exception:
        #         log.error(exception)
        #         return []
        # else:
        return np.fromiter(tls_client_hello.values(), dtype=float)
