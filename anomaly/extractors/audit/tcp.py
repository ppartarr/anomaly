#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

import logging as log
import numpy as np

from anomaly.extractors.protocols import convert_protocol_name_to_number
from anomaly.models.online.kitnet.stats.connection import ConnectionStatistics
from anomaly.readers.socket import SocketReader
from anomaly.utils import mac_to_decimal, ipv4_to_decimal, ipv6_to_decimal, convert_ip_address_to_decimal


class TCPFeatureExtractor:
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

        tcp = {
            'Timestamp': row[0],
            'SrcPort': row[1],
            'DstPort': row[2],
            'SeqNum': row[3],
            'AckNum': row[4],
            'DataOffset': row[5],
            'FIN': row[6],
            'SYN': row[7],
            'RST': row[8],
            'PSH': row[9],
            'ACK': row[10],
            'URG': row[11],
            'ECE': row[12],
            'CWR': row[13],
            'NS': row[14],
            'Window': row[15],
            'Checksum': row[16],
            'Urgent': row[17],
            'PayloadEntropy': row[18],
            'PayloadSize': row[19],
            'SrcIP': row[20],
            'DstIP': row[21]
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
        return np.fromiter(tcp.values(), dtype=float)
