#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

import logging as log
import numpy as np

from anomaly.extractors.protocols import convert_protocol_name_to_number
from anomaly.models.online.kitnet.stats.connection import ConnectionStatistics
from anomaly.readers.socket import SocketReader
from anomaly.utils import mac_to_decimal, ipv4_to_decimal, ipv6_to_decimal, convert_ip_address_to_decimal


class NTPFeatureExtractor:
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
        num_features = 19

        log.info('There are {num_headers} features'.format(num_headers=num_features))
        return num_features

    def get_next_vector(self):
        row = self.reader.get_next_row()
        if row == []:
            return []

        ntp = {
            'Timestamp': row[0],
            'LeapIndicator': row[1],
            'Version': row[2],
            'Mode': row[3],
            'Stratum': row[4],
            'Poll': row[5],
            'Precision': row[6],
            'RootDelay': row[7],
            'RootDispersion': row[8],
            'ReferenceID': row[9],
            'ReferenceTimestamp': row[10],
            'OriginTimestamp': row[11],
            'ReceiveTimestamp': row[12],
            'TransmitTimestamp': row[13],
            'ExtensionBytes': row[14],
            'SrcIP': row[15],
            'DstIP': row[16],
            'SrcPort': row[17],
            'DstPort': row[18]
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
        return np.fromiter(ntp.values(), dtype=float)
