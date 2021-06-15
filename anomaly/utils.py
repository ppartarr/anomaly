#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

from sklearn.preprocessing import StandardScaler
from sklearn.feature_selection import SelectKBest
from sklearn.impute import SimpleImputer
from sklearn.metrics import roc_auc_score, f1_score
from pandas.api.types import is_numeric_dtype, is_string_dtype

from anomaly.columns import csv_dtypes, pcap_dtypes
from anomaly.models.kitnet.stats.network import NetworkStatistics
import anomaly.config as config

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

log = log.getLogger(__name__)


def process_labels(y):
    """Convert the labels into numerical values"""

    log.info('Processing labels...')

    # set all malicious labels to -1
    # label names obtained from stats.py
    anomaly_labels = [
        'DoS attacks-SlowHTTPTest',
        'DoS attacks-GoldenEye',
        'DoS attacks-Hulk',
        'DoS attacks-Slowloris',
        'DDOS attack-LOIC-UDP',
        'DDoS attacks-LOIC-HTTP',
        'DDOS attack-HOIC',
        'SSH-Bruteforce',
        'Brute Force -Web',
        'Brute Force -XSS',
        'FTP-BruteForce',
        'SQL Injection',
        'Bot',
        'Infilteration'
    ]
    y.replace(anomaly_labels, -1, inplace=True)

    # set normal label to 1
    y.replace('Benign', 1, inplace=True)

    return y


def process_infinity(x):
    """Replace all the Infinity values with the column's max"""
    log.info('Processing Infinity values...')
    inf_columns = x.columns[np.isinf(x).any()]
    for column in inf_columns:
        # replace Infinity with column max
        inf = x.loc[x[column] != np.inf, column].max()
        x[column].replace(np.inf, inf, inplace=True)
    return x


def process_nan(x):
    """Replace all the NaN values with the column's median"""
    log.info('Processing NaN values...')
    nan_columns = x.loc[:, x.isna().any()].columns
    for column in nan_columns:
        if is_numeric_dtype(x[column]):
            mean = x[column].mean()
            x[column].fillna(mean, inplace=True)
        elif is_string_dtype(x[column]):
            # TODO: this works for IP addresses but maybe not other object/string types
            x[column].fillna(-1, inplace=True)
    # imputer = SimpleImputer(missing_values=np.nan, strategy='mean')
    # x = pd.DataFrame(data=imputer.fit_transform(x.values), columns=x.columns)
    return x


def date_to_timestamp(date):
    """Convert a date in the following format 02/03/2018 08:47:38 to a unix timestamp"""
    return pd.Timestamp(date).timestamp()


def drop_constant_columns(x):
    """Remove the columns with constant values"""
    for column in x.columns:
        if len(x[column].value_counts()) == 1:
            x = x.drop([column], axis=1)
    return x


def drop_invalid_rows(x):
    """The CIC 2018 dataset network flow data has invalid rows which are a duplicate of the csv headers - drop them!"""
    return x[x.Timestamp != 'Timestamp']


def process_csv(filepath):
    """Ingest the raw csv data and run pre-processing tasks"""

    log.info('Opening {}...'.format(filepath))

    # NOTE: we cannot use dtype & converters so we convert the columns manually later
    chunks = pd.read_csv(filepath, dtype=csv_dtypes, chunksize=config.chunksize)

    x_list = []
    y_list = []

    for chunk in chunks:
        chunk = drop_invalid_rows(chunk)

        y = process_labels(chunk.Label)

        # x = chunk.drop(['Timestamp'], axis=1)
        chunk.Timestamp = chunk.Timestamp.apply(date_to_timestamp)
        chunk.drop(['Label'], axis=1, inplace=True)

        if 'Flow ID' in chunk.columns:
            # TODO: use the Flow ID
            chunk['Flow ID'] = chunk['Flow ID'].astype('category').cat.codes
            chunk['Src IP'] = chunk['Src IP'].apply(convert_ip_address_to_decimal)
            chunk['Dst IP'] = chunk['Dst IP'].apply(convert_ip_address_to_decimal)
            # chunk.drop(['Flow ID'], axis=1, inplace=True)

        x = chunk
        x = process_infinity(x)
        x = process_nan(x)

        # NOTE: don't drop columns when reading from multiple files since value might vary across files
        # x = drop_constant_columns(x)
        x_list.append(x)
        y_list.append(y)

    return pd.concat(x_list), pd.concat(y_list)


def process_pcap(filepath):
    """Ingest the raw pcap data and run pre-processing tasks"""

    log.info('Opening {}...'.format(filepath))

    # find file
    if not os.path.isfile(filepath):
        log.info('File {file} does not exist'.format(file=filepath))
        raise Exception()

    # check file type
    filetype = filepath.split('.')[-1]

    tshark = get_tshark_path()

    # convert pcap to tsv if necessary
    if filetype == "pcap" or filetype == 'pcapng' or filetype == "tsv":
        tshark_filepath = filepath + ".tsv"

        # try parsing via tshark dll of wireshark
        if os.path.isfile(tshark) and not os.path.exists(tshark_filepath):
            pcap2tsv_with_tshark(tshark, filepath)  # creates local tsv file
    else:
        log.error('File {filepath} is not a tsv or pcap file'.format(filepath=filepath))
        raise Exception()

    chunks = pd.read_table(tshark_filepath, dtype=pcap_dtypes, chunksize=config.chunksize)

    x_list = []

    for chunk in chunks:
        x = chunk
        # x = process_infinity(x)
        x = process_nan(x)
        x = process_addresses(x)

        # NOTE: comment out to disable additional statistical features from Kitsune
        x = feature_engineering(x)
        x_list.append(x)

    # NOTE: don't drop columns when reading from multiple files since value might vary across files
    # x = drop_constant_columns(x)
    return pd.concat(x_list)


def feature_engineering(x):
    """Add features based on network statistics"""
    maxHost = 255
    maxSess = 255
    netStats = NetworkStatistics(np.nan, maxHost, maxSess)

    x.apply(lambda row: feature_stats(row, netStats))

    return x


def feature_stats(row, netStats):
    # print(row)
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


def process_addresses(x):
    """Convert MAC & IP addresses to decimal values"""
    log.info('Processing addresses...')
    x['eth.src'] = x['eth.src'].apply(mac_to_decimal)
    x['eth.dst'] = x['eth.dst'].apply(mac_to_decimal)
    x['arp.src.hw_mac'] = x['arp.src.hw_mac'].apply(mac_to_decimal)
    x['arp.dst.hw_mac'] = x['arp.dst.hw_mac'].apply(mac_to_decimal)

    # x['ip.src'].fillna(-1, inplace=True)
    x['ip.src'] = x['ip.src'].apply(ipv4_to_decimal)
    x['ip.dst'] = x['ip.dst'].apply(ipv4_to_decimal)
    x['arp.src.proto_ipv4'] = x['arp.src.proto_ipv4'].apply(ipv4_to_decimal)
    x['arp.dst.proto_ipv4'] = x['arp.dst.proto_ipv4'].apply(ipv4_to_decimal)

    x['ipv6.src'] = x['ipv6.src'].apply(ipv6_to_decimal)
    x['ipv6.dst'] = x['ipv6.dst'].apply(ipv6_to_decimal)
    return x


def get_tshark_path():
    """Return the tshark path"""
    system_path = os.environ['PATH']
    for path in system_path.split(os.pathsep):
        filename = os.path.join(path, 'tshark')
        if os.path.isfile(filename):
            return filename


def pcap2tsv_with_tshark(tshark, filepath):
    print('Parsing with tshark...')
    fields = '-e frame.time_epoch -e frame.len -e eth.src -e eth.dst -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e icmp.type -e icmp.code -e arp.opcode -e arp.src.hw_mac -e arp.src.proto_ipv4 -e arp.dst.hw_mac -e arp.dst.proto_ipv4 -e ipv6.src -e ipv6.dst'
    cmd = '"' + tshark + '" -r ' + filepath + ' -T fields ' + fields + ' -E header=y -E occurrence=f > '+filepath+".tsv"
    subprocess.call(cmd, shell=True)
    print('tshark parsing complete. File saved as {filepath}.tsv'.format(filepath=filepath))


def mac_to_decimal(mac_addr):
    if mac_addr == -1:
        return mac_addr
    else:
        return int(str(mac_addr).replace(':', ''), 16)


def ipv4_to_decimal(ipv4_addr):
    if ipv4_addr == -1:
        return ipv4_addr
    else:
        return int(IPv4Address(ipv4_addr))


def ipv6_to_decimal(ipv6_addr):
    if ipv6_addr == -1:
        return ipv6_addr
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
