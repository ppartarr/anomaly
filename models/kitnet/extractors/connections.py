#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

import logging as log
import numpy as np
import csv
import os
import ipaddress

from anomaly.models.kitnet.extractors.protocols import convert_protocol_name_to_number
from anomaly.models.kitnet.stats.connection import ConnectionStatistics
from anomaly.utils import mac_to_decimal, convert_ip_address_to_decimal


class ConnectionFeatureExtractor:
    SOCKET_NAME = 'Connection.sock'

    def __init__(self, file_path, socket, limit=np.inf):
        self.file_path = file_path
        self.socket = socket
        self.limit = limit
        self.current_packet_index = 0

        # Prepare csv file
        if file_path:
            self.__prep__()

        # Prep feature extractor
        max_hosts = 100000000000
        max_sessions = 100000000000
        self.connection_statistics = ConnectionStatistics(np.nan, max_hosts, max_sessions)

    def __prep__(self):
        # Find file
        if not os.path.isfile(self.file_path):  # file does not exist
            raise Exception('File {file_path} does not exist'.format(file_path=self.file_path))

        # check file type
        type = self.file_path.split('.')[-1]

        if type == "csv":
            # NOTE: if overflowing, re-introduce maxInt from kitsune
            log.info("counting lines in file...")
            num_lines = sum(1 for line in open(self.file_path))
            log.info('There are {num_lines} packets'.format(num_lines=num_lines))
            self.limit = min(self.limit, num_lines-1)
            self.csv_stream = open(self.file_path, 'rt', encoding="utf8")
            self.csv_iterator = csv.reader(self.csv_stream, delimiter='\t')
            # NOTE: move iterator past comment and header
            row = self.csv_iterator.__next__().__next__()
        else:
            raise Exception('File {file_path} is not a csv file'.format(file_path=self.file_path))

    def get_next_vector(self):
        if self.current_packet_index == self.limit:
            self.csv_stream.close()
            return []

        # Parse next packet
        row = self.csv_iterator.__next__()
        connection = Connection(
            row[0],
            convert_protocol_name_to_number(row[1]),
            convert_protocol_name_to_number(row[2]),
            convert_protocol_name_to_number(row[3]),
            convert_protocol_name_to_number(row[4]),
            mac_to_decimal(row[5]),
            mac_to_decimal(row[6]),
            convert_ip_address_to_decimal(row[7]),
            row[8],
            convert_ip_address_to_decimal(row[9]),
            row[10],
            row[11],
            row[12],
            row[13],
            row[14],
            row[15],
            row[16]
        )

        try:
            return self.connection_statistics.update_get_stats(connection)
        except Exception as exception:
            log.error(exception)
            return []


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
                 uid,
                 duration,
                 timestamp_end):
        self.timestamp_start = timestamp_start
        self.link_protocol = link_protocol
        self.network_protocol = network_protocol
        self.transport_protocol = transport_protocol
        self.application_protocol = application_protocol
        self.srcMAC = srcMAC
        self.dstMAC = dstMAC
        self.srcIP = srcIP
        self.src_port = src_port
        self.dstIP = dstIP
        self.dst_port = dst_port
        self.total_size = total_size
        self.payload_size = payload_size
        self.num_packets = num_packets
        self.uid = uid
        self.duration = duration
        self.timestamp_end = timestamp_end
