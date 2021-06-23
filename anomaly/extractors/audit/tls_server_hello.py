#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

import logging as log
import numpy as np

from anomaly.extractors.protocols import convert_protocol_name_to_number
from anomaly.models.online.kitnet.stats.connection import ConnectionStatistics
from anomaly.readers.socket import SocketReader
from anomaly.utils import mac_to_decimal, ipv4_to_decimal, ipv6_to_decimal, convert_ip_address_to_decimal


class TLSServerHelloFeatureExtractor:
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
        num_features = 25

        log.info('There are {num_headers} features'.format(num_headers=num_features))
        return num_features

    def get_next_vector(self):
        row = self.reader.get_next_row()
        if row == []:
            return []

        tls_server_hello = {
            'Timestamp': row[0],
            'Version': row[1],
            'CipherSuite': row[2],
            'CompressionMethod': row[3],
            'NextProtoNeg': row[4],
            'NextProtos': row[5],
            'OCSPStapling': row[6],
            'TicketSupported': row[7],
            'SecureRenegotiationSupported': row[8],
            'SecureRenegotiation': row[9],
            'AlpnProtocol': row[10],
            'Ems': row[11],
            'SupportedVersion': row[12],
            'SelectedIdentityPresent': row[13],
            'SelectedIdentity': row[14],
            'Cookie': row[15],
            'SelectedGroup': row[16],
            'Extensions': row[17],
            'SrcIP': row[18],
            'DstIP': row[19],
            'SrcMAC': row[20],
            'DstMAC': row[21],
            'SrcPort': row[22],
            'DstPort': row[23],
            'Ja3S': row[24]
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
        return np.fromiter(tls_server_hello.values(), dtype=float)
