#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

import logging as log
import numpy as np

from anomaly.extractors.protocols import convert_protocol_name_to_number
from anomaly.models.online.kitnet.stats.connection import ConnectionStatistics
from anomaly.readers.socket import SocketReader
from anomaly.utils import mac_to_decimal, ipv4_to_decimal, ipv6_to_decimal, convert_ip_address_to_decimal


class DHCPv4ProfileFeatureExtractor:
    def __init__(self, path, reader, limit=np.inf, encoded=False):
        self.path = path
        self.reader = reader(path, limit)
        self.limit = limit
        self.encoded = encoded

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

        dhcpv4 = {
            'Timestamp': row[0],
            'Operation': row[1],
            'HardwareType': row[2],
            'HardwareLen': row[3],
            'HardwareOpts': row[4],
            'Xid': row[5],
            'Secs': row[6],
            'Flags': row[7],
            'ClientIP': row[8],
            'YourClientIP': row[9],
            'NextServerIP': row[10],
            'RelayAgentIP': row[11],
            'ClientHWAddr': row[12],
            'ServerName': row[13],
            'File': row[14],
            'SrcIP': row[15],
            'DstIP': row[16],
            'SrcPort': row[17],
            'DstPort': row[18],
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
        return np.fromiter(dhcpv4.values(), dtype=float)
