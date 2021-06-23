#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

import logging as log
import numpy as np

from anomaly.extractors.protocols import convert_protocol_name_to_number
from anomaly.models.online.kitnet.stats.connection import ConnectionStatistics
from anomaly.readers.socket import SocketReader
from anomaly.utils import mac_to_decimal, ipv4_to_decimal, ipv6_to_decimal, convert_ip_address_to_decimal


class DNSFeatureExtractor:
    def __init__(self, path, reader, limit=np.inf, encoded=False, labelled=False):
        self.path = path
        self.reader = reader(path, limit)
        self.limit = limit
        self.encoded = encoded
        self.labelled = labelled

        # skip comment & header if reading from netcap audit record csv
        if isinstance(self.reader, SocketReader):
            self.reader.get_next_row()
            self.reader.get_next_row()

        # Prep feature extractor
        # max_hosts = 100000000000
        # max_sessions = 100000000000

        # self.connection_statistics = ConnectionStatistics(np.nan, max_hosts, max_sessions)

    def get_num_features(self):
        num_features = 22

        log.info('There are {num_headers} features'.format(num_headers=num_features))
        return num_features

    def get_next_vector(self):
        row = self.reader.get_next_row()
        if row == []:
            return []

        dns = {
            'Timestamp': row[0],
            'ID': row[1],
            'QR': row[2],
            'OpCode': row[3],
            'AA': row[4],
            'TC': row[5],
            'RD': row[6],
            'RA': row[7],
            'Z': row[8],
            'ResponseCode': row[9],
            'QDCount': row[10],
            'ANCount': row[11],
            'NSCount': row[12],
            'ARCount': row[13],
            'Questions': row[14],
            'Answers': row[15],
            'Authorities': row[16],
            'Additionals': row[17],
            'SrcIP': row[18],
            'DstIP': row[19],
            'SrcPort': row[20],
            'DstPort': row[21]
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
        return np.fromiter(dns.values(), dtype=float)
