#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

import logging as log
import numpy as np

from anomaly.extractors.protocols import convert_protocol_name_to_number
from anomaly.models.online.kitnet.stats.connection import ConnectionStatistics
from anomaly.readers.socket import SocketReader
from anomaly.utils import mac_to_decimal, ipv4_to_decimal, ipv6_to_decimal, convert_ip_address_to_decimal


class IGMPFeatureExtractor:
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
        num_features = 15

        log.info('There are {num_headers} features'.format(num_headers=num_features))
        return num_features

    def get_next_vector(self):
        row = self.reader.get_next_row()
        if row == []:
            return []

        igmp = {
            'Timestamp': row[0],
            'Type': row[1],
            'MaxResponseTime': row[2],
            'Checksum': row[3],
            'GroupAddress': row[4],
            'SupressRouterProcessing': row[5],
            'RobustnessValue': row[6],
            'IntervalTime': row[7],
            'SourceAddresses': row[8],
            'NumberOfGroupRecords': row[9],
            'NumberOfSources': row[10],
            'GroupRecords': row[11],
            'Version': row[12],
            'SrcIP': row[13],
            'DstIP': row[14]
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
        return np.fromiter(igmp.values(), dtype=float)
