#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

from sklearn.preprocessing import StandardScaler
from sklearn.feature_selection import SelectKBest
from sklearn.impute import SimpleImputer
from sklearn.metrics import roc_auc_score, f1_score
from pandas.api.types import is_numeric_dtype, is_string_dtype

from anomaly.columns import csv_dtypes, pcap_dtypes, best_30, tsv_columns
from anomaly.models.online.kitnet.stats.network import NetworkStatistics
from anomaly.models.online.kitnet.stats.connection import ConnectionStatistics
import anomaly.config as config
from anomaly.extractors.protocols import convert_protocol_name_to_number

from ipaddress import IPv4Address, IPv6Address, ip_address

import numpy as np
import pandas as pd
import argparse
import matplotlib.pyplot as plt
import os
import subprocess
import csv
import sys
import logging as log

import dask.dataframe as dd
import dask


def process_netcap_label(y):
    """Convert the labels into numerical values"""

    malicious = {
        'bruteforce',
        'denial-of-service',
        'injection',
        'infiltration',
        'botnet',
        'normal'
    }

    if y in malicious:
        return 1
    elif y == 'normal':
        return 0
    else:
        log.error("netcap label doesn't exist")
        return -1


def drop_infinity(x):
    """Drop all the Infinity value rows"""
    log.info('Processing Infinity values...')
    return x[~x.isin([np.inf, -np.inf]).any(1)]


def replace_infinity(x):
    """Replace all the Infinity values with the column's max"""
    log.info('Processing Infinity values...')
    inf_columns = x.columns[np.isinf(x).any()]
    for column in inf_columns:
        # replace Infinity with column max
        inf = x.loc[x[column] != np.inf, column].max()
        x[column].replace(np.inf, inf, inplace=True)
    return x


def drop_nan(x):
    """Drop all the NaN value rows"""
    log.info('Processing NaN values...')
    return x[~x.isin([np.nan]).any(1)]


def replace_nan(x):
    """Replace all the NaN values with -1"""
    log.info('Processing NaN values...')
    return x.fillna(-1)
    # for column in x.columns:
    # log.info('{col} {t}'.format(col=column, t=x[column].dtype))
    # x[column].fillna(-1)
    # if is_numeric_dtype(x[column]):
    #     mean = x[column].mean()
    #     x[column] = x[column].fillna(mean)
    # elif is_string_dtype(x[column]):
    #     # TODO: this works for IP addresses but maybe not other object/string types
    #     x[column].fillna(-1)
    # return x


def date_to_timestamp(date):
    """Convert a date in the following format 02/03/2018 08:47:38 to a unix timestamp"""
    return pd.Timestamp(date).timestamp()


def drop_constant_columns(x):
    """Remove the columns with constant values"""
    for column in x.columns:
        if len(x[column].value_counts()) == 1:
            x = x.drop([column], axis=1)
    return x


def get_columns(x, columns):
    """Note: This also drops the Label & Flow ID columns"""
    columns_to_drop = []
    for column in x.columns:
        if column not in columns:
            columns_to_drop.append(column)

    x = x.drop(labels=columns_to_drop, axis=1)
    return x


def process_csv_kitsune(filepath):
    """Ingest the raw csv data and run pre-processing tasks"""
    log.info('Opening {}...'.format(filepath))

    maxHost = 1000000
    maxSess = 1000000
    connStats = ConnectionStatistics(np.nan, maxHost, maxSess)

    # NOTE: we cannot use dtype & converters so we convert the columns manually later
    chunks = pd.read_csv(filepath, chunksize=config.chunksize, na_values=['  ', '\r\t', '\t', '', 'nan'])

    x_list = []
    y_list = []

    for chunk in chunks:

        x = chunk
        x = drop_infinity(x)
        x = drop_nan(x)
        # x = x.astype(dtype=csv_dtypes)

        values = chunk.apply(lambda row: connection_stats(row, connStats), axis=1)

        # log.info('VALUES')
        # log.info(values)
        x, y = values

        y = process_labels(y)

        x_list.append(x)
        y_list.append(y)

    return pd.concat(x_list), pd.concat(y_list)


def connection_stats(row, connStats):
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

    label = row[18]

    # Parse next packet
    try:
        connection = Connection(**conn)
        log.info(connStats.update_get_stats(connection))
        log.info(label)
        return connStats.update_get_stats(connection), label
    except Exception as exception:
        log.error(exception)
        return []

    return connStats.update_get_stats(connection), label


def feature_engineering(x):
    """Add features based on network statistics"""
    maxHost = 255
    maxSess = 255
    netStats = NetworkStatistics(np.nan, maxHost, maxSess)

    x.compute().apply(lambda row: feature_stats(row, connection_stats))

    return x


def feature_stats(row, netStats):
    IPtype = np.nan
    timestamp = row[0]
    framelen = row[1]
    srcIP = ''
    dstIP = ''
    if row[4] != '':  # IPv4
        srcIP = row[4]
        dstIP = row[5]
        IPtype = 0
    elif row[17] != '':  # ipv6
        srcIP = row[17]
        dstIP = row[18]
        IPtype = 1
    # UDP or TCP port: the concatenation of the two port strings will will results in an OR "[tcp|udp]"
    srcproto = row[6] + row[8]
    dstproto = row[7] + row[9]  # UDP or TCP port
    srcMAC = row[2]
    dstMAC = row[3]
    if srcproto == '':  # it's a L2/L1 level protocol
        if row[12] != '':  # is ARP
            srcproto = 'arp'
            dstproto = 'arp'
            srcIP = row[14]  # src IP (ARP)
            dstIP = row[16]  # dst IP (ARP)
            IPtype = 0
        elif row[10] != '':  # is ICMP
            srcproto = 'icmp'
            dstproto = 'icmp'
            IPtype = 0
        elif srcIP + srcproto + dstIP + dstproto == '':  # some other protocol
            srcIP = row[2]  # src MAC
            dstIP = row[3]  # dst

    return netStats.update_get_stats(IPtype,
                                     srcMAC,
                                     dstMAC,
                                     srcIP,
                                     srcproto,
                                     dstIP,
                                     dstproto,
                                     int(framelen),
                                     float(timestamp))


def drop_addresses(x, columns):
    log.info('Dropping all MAC, IPv4 and IPv6 columns...')
    x.drop()


def process_addresses(x):
    """Convert MAC & IP addresses to decimal values"""
    log.info('Processing addresses...')
    x['eth.src'] = x['eth.src'].apply(mac_to_decimal, meta=int)
    x['eth.dst'] = x['eth.dst'].apply(mac_to_decimal, meta=int)
    x['arp.src.hw_mac'] = x['arp.src.hw_mac'].apply(mac_to_decimal, meta=int)
    x['arp.dst.hw_mac'] = x['arp.dst.hw_mac'].apply(mac_to_decimal, meta=int)

    # x['ip.src'].fillna(-1, inplace=True)
    x['ip.src'] = x['ip.src'].apply(ipv4_to_decimal, meta=int)
    x['ip.dst'] = x['ip.dst'].apply(ipv4_to_decimal, meta=int)
    x['arp.src.proto_ipv4'] = x['arp.src.proto_ipv4'].apply(ipv4_to_decimal, meta=int)
    x['arp.dst.proto_ipv4'] = x['arp.dst.proto_ipv4'].apply(ipv4_to_decimal, meta=int)

    x['ipv6.src'] = x['ipv6.src'].apply(ipv6_to_decimal, meta=int)
    x['ipv6.dst'] = x['ipv6.dst'].apply(ipv6_to_decimal, meta=int)
    return x


def get_tshark_path():
    """Return the tshark path"""
    system_path = os.environ['PATH']
    for path in system_path.split(os.pathsep):
        filename = os.path.join(path, 'tshark')
        if os.path.isfile(filename):
            return filename


def pcap2tsv_with_tshark(tshark, filepath):
    log.info('Parsing with tshark...')
    fields = '-e frame.time_epoch -e frame.len -e eth.src -e eth.dst -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e icmp.type -e icmp.code -e arp.opcode -e arp.src.hw_mac -e arp.src.proto_ipv4 -e arp.dst.hw_mac -e arp.dst.proto_ipv4 -e ipv6.src -e ipv6.dst'
    cmd = '"' + tshark + '" -r ' + filepath + ' -T fields ' + fields + ' -E header=y -E occurrence=f > '+filepath+".tsv"
    subprocess.call(cmd, shell=True)
    log.info('tshark parsing complete. File saved as {filepath}.tsv'.format(filepath=filepath))


def mac_to_decimal(mac_addr):
    if mac_addr == -1:
        return -1
    else:
        return int(str(mac_addr).replace(':', ''), 16)


def ipv4_to_decimal(ipv4_addr):
    if ipv4_addr == -1:
        return -1
    else:
        return int(IPv4Address(ipv4_addr))


def ipv6_to_decimal(ipv6_addr):
    if ipv6_addr == -1 or (type(ipv6_addr) == float and np.isnan(ipv6_addr)):
        return -1
    else:
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
