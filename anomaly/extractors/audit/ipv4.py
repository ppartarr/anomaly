#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

import logging as log
import numpy as np

from anomaly.extractors.protocols import convert_protocol_name_to_number
from anomaly.models.online.kitnet.stats.connection import ConnectionStatistics
from anomaly.utils import mac_to_decimal, ipv4_to_decimal, ipv6_to_decimal, convert_ip_address_to_decimal


class IPv4FeatureExtractor:
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
        num_features = 15

        log.info('There are {num_headers} features'.format(num_headers=num_features))
        return num_features

    def get_next_vector(self):
        row = self.reader.get_next_row()
        if row == []:
            return []

        ipv4 = {
            'Timestamp': row[0],
            'Version': row[1],
            'IHL': row[2],
            'TOS': row[3],
            'Length': row[4],
            'Id': row[5],
            'Flags': row[6],
            'FragOffset': row[7],
            'TTL': row[8],
            'Protocol': row[9],
            'Checksum': row[10],
            'SrcIP': row[11],
            'DstIP': row[12],
            'PayloadEntropy': row[13],
            'PayloadSize': row[14]

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
        return np.fromiter(ipv4.values(), dtype=float)
