#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

import logging as log
import numpy as np

from anomaly.extractors.protocols import convert_protocol_name_to_number
from anomaly.models.online.kitnet.stats.connection import ConnectionStatistics
from anomaly.readers.socket import SocketReader
from anomaly.utils import mac_to_decimal, ipv4_to_decimal, ipv6_to_decimal, convert_ip_address_to_decimal


class ConnectionFeatureExtractor:
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
        max_hosts = 100000000000
        max_sessions = 100000000000

        self.connection_statistics = ConnectionStatistics(np.nan, max_hosts, max_sessions)

    def get_num_features(self):
        if not self.encoded:
            num_features = len(self.connection_statistics.get_net_stat_headers())
        else:
            num_features = 18

        log.info('There are {num_headers} features'.format(num_headers=num_features))
        return num_features

    def get_next_vector(self):
        row = self.reader.get_next_row()
        if row == []:
            return []

        conn = {
            'timestamp_start': row[0],
            'link_protocol': row[1],
            'network_protocol': row[2],
            'transport_protocol': row[3],
            'application_protocol': row[4],
            'srcMAC': row[5],
            'dstMAC': row[6],
            'srcIP': row[7],
            'src_port': row[8],
            'dstIP': row[9],
            'dst_port': row[10],
            'total_size': row[11],
            'payload_size': row[12],
            'num_packets': row[13],
            'duration': row[14],
            'timestamp_end': row[15],
            'num_client_bytes': row[16],
            'num_server_bytes': row[17]
        }

        if self.labelled:
            label = row[18]
        else:
            label = None

        if not self.encoded:
            # Parse next packet
            try:
                connection = Connection(**conn)
                return self.connection_statistics.update_get_stats(connection), label
            except Exception as exception:
                log.error(exception)
                return []
        else:
            return np.fromiter(conn.values(), dtype=float), label


class Connection:
    """Represents a netcap connection from an audit record"""

    def __init__(self,
                 timestamp_start,
                 link_protocol,
                 network_protocol,
                 transport_protocol,
                 application_protocol,
                 srcMAC,
                 dstMAC,
                 srcIP,
                 src_port,
                 dstIP,
                 dst_port,
                 total_size,
                 payload_size,
                 num_packets,
                 duration,
                 timestamp_end,
                 num_client_bytes,
                 num_server_bytes):

        self.timestamp_start = np.int64(timestamp_start)
        self.link_protocol = np.int8(convert_protocol_name_to_number(link_protocol))
        self.network_protocol = np.int8(convert_protocol_name_to_number(network_protocol))
        self.transport_protocol = np.int8(convert_protocol_name_to_number(transport_protocol))
        self.application_protocol = np.int8(convert_protocol_name_to_number(application_protocol))
        self.srcMAC = np.int64(mac_to_decimal(check_numeric_empty(srcMAC)))
        self.dstMAC = np.int64(mac_to_decimal(check_numeric_empty(dstMAC)))
        self.srcIP = int(convert_ip_address_to_decimal(check_numeric_empty(srcIP)))
        self.src_port = np.int8(check_numeric_empty(src_port))
        self.dstIP = int(convert_ip_address_to_decimal(check_numeric_empty(dstIP)))
        self.dst_port = np.int8(check_numeric_empty(dst_port))
        self.total_size = np.int32(check_numeric_empty(total_size))
        self.payload_size = np.int32(check_numeric_empty(payload_size))
        self.num_packets = np.int32(check_numeric_empty(num_packets))
        self.duration = np.int64(check_numeric_empty(duration))
        self.timestamp_end = np.int64(check_numeric_empty(timestamp_end))
        self.num_client_bytes = np.int64(check_numeric_empty(num_client_bytes))
        self.num_server_bytes = np.int64(check_numeric_empty(num_server_bytes))


def check_numeric_empty(data):
    """Checks if a numeric audit record parsed value is empty, return -1 if it is"""
    if data == '':
        return -1
    else:
        return data
