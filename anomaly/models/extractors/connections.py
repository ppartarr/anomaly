#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

import logging as log
import numpy as np
from ipaddress import IPv4Address, IPv6Address, ip_address

from anomaly.models.extractors.protocols import convert_protocol_name_to_number
from anomaly.models.kitnet.stats.connection import ConnectionStatistics
from anomaly.models.readers.csv import CSVReader  # , SocketReader


class ConnectionFeatureExtractor:
    SOCKET_NAME = 'Connection.sock'

    def __init__(self, path, reader, limit=np.inf):
        self.path = path
        self.reader = reader(path, limit)
        self.limit = limit

        # Prep feature extractor
        max_hosts = 100000000000
        max_sessions = 100000000000
        self.connection_statistics = ConnectionStatistics(np.nan, max_hosts, max_sessions)

    def get_num_features(self):
        log.info('There are {num_headers} features'.format(
            num_headers=len(self.connection_statistics.get_net_stat_headers())))
        return len(self.connection_statistics.get_net_stat_headers())

    def get_next_vector(self):
        row = self.reader.get_next_row()
        if row == []:
            return []

        # Parse next packet
        # log.info(self.current_packet_index)
        # log.info(self.limit)
        # log.info(row)
        connection = Connection(
            timestamp_start=row[0],
            link_protocol=row[1],
            network_protocol=row[2],
            transport_protocol=row[3],
            application_protocol=row[4],
            srcMAC=row[5],
            dstMAC=row[6],
            srcIP=row[7],
            src_port=row[8],
            dstIP=row[9],
            dst_port=row[10],
            total_size=row[11],
            payload_size=row[12],
            num_packets=row[13],
            uid=row[14],
            duration=row[15],
            timestamp_end=row[16]
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
        # NOTE: debug
        # log.info('timestamp_start: {data}'.format(data=timestamp_start))
        # log.info('link_protocol: {data}'.format(data=link_protocol))
        # log.info('network_protocol: {data}'.format(data=network_protocol))
        # log.info('transport_protocol: {data}'.format(data=transport_protocol))
        # log.info('application_protocol: {data}'.format(data=application_protocol))
        # log.info('srcMAC: {data}'.format(data=srcMAC))
        # log.info('dstMAC: {data}'.format(data=dstMAC))
        # log.info('srcIP: {data}'.format(data=srcIP))
        # log.info('src_port: {data}'.format(data=src_port))
        # log.info('dstIP: {data}'.format(data=dstIP))
        # log.info('dst_port: {data}'.format(data=dst_port))
        # log.info('total_size: {data}'.format(data=total_size))
        # log.info('payload_size: {data}'.format(data=payload_size))
        # log.info('num_packets: {data}'.format(data=num_packets))
        # log.info('uid: {data}'.format(data=uid))
        # log.info('duration: {data}'.format(data=duration))
        # log.info('timestamp_end: {data}'.format(data=timestamp_end))

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
        self.uid = np.str(check_numeric_empty(uid))
        self.duration = np.int64(check_numeric_empty(duration))
        self.timestamp_end = np.int64(check_numeric_empty(timestamp_end))


def check_numeric_empty(data):
    """Checks if a numeric audit record parsed value is empty, return -1 if it is"""
    if data == '':
        return -1
    else:
        return data

# TODO: remove duplicate code and use utils once imports are fixed


def mac_to_decimal(mac_addr):
    if mac_addr == -1:
        return mac_addr
    else:
        return int(str(mac_addr).replace(':', ''), 16)


def ipv4_to_decimal(ipv4_addr):
    if ipv4_addr == -1:
        return ipv4_addr
    else:
        # return struct.unpack('!L', socket.inet_aton(str(ipv4_addr)))[0]
        return int(IPv4Address(ipv4_addr))


def ipv6_to_decimal(ipv6_addr):
    # print(ipv6_addr)
    if ipv6_addr == -1:
        return ipv6_addr
    else:
        # return struct.unpack('!L', socket.inet_aton(str(ipv6_addr)))[0]
        return int(IPv6Address(ipv6_addr))


def convert_ip_address_to_decimal(ip_addr):
    if ip_addr == -1:
        return -1
    else:
        ip_addr = ip_address(ip_addr)
        if ip_addr.version == 4:
            return ipv4_to_decimal(ip_addr)
        elif ip_addr.version == 6:
            return ipv6_to_decimal(ip_addr)
        else:
            log.error('Cannot convert ip address {ip_addr} to decimal'.format(ip_addr=ip_addr))
