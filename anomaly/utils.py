#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

from sklearn.preprocessing import StandardScaler
from sklearn.feature_selection import SelectKBest
from sklearn.impute import SimpleImputer
from sklearn.metrics import roc_auc_score, f1_score
from pandas.api.types import is_numeric_dtype, is_string_dtype

from anomaly.columns import csv_dtypes, pcap_dtypes, best_30, tsv_columns
from anomaly.models.online.kitnet.stats.network import NetworkStatistics
import anomaly.config as config

from ipaddress import IPv4Address, IPv6Address, ip_address

import numpy as np
import pandas as pd
import dask.dataframe as dd
import argparse
import matplotlib.pyplot as plt
import os
import subprocess
import csv
import sys
import logging as log
import dask

log = log.getLogger(__name__)


def process_labels(y):
    """Convert the labels into numerical values"""

    log.info('Processing labels...')

    # set all malicious labels to -1
    # label names obtained from stats.py
    labels = {
        'DoS attacks-SlowHTTPTest': 1,
        'DoS attacks-GoldenEye': 1,
        'DoS attacks-Hulk': 1,
        'DoS attacks-Slowloris': 1,
        'DDOS attack-LOIC-UDP': 1,
        'DDoS attacks-LOIC-HTTP': 1,
        'DDOS attack-HOIC': 1,
        'SSH-Bruteforce': 1,
        'Brute Force -Web': 1,
        'Brute Force -XSS': 1,
        'FTP-BruteForce': 1,
        'SQL Injection': 1,
        'Bot': 1,
        'Infilteration': 1,
        'Benign': 0
    }

    y = y.replace(to_replace=labels)
    return y


def process_netcap_labels(y):
    """Convert the labels into numerical values"""

    labels = {
        'bruteforce': 1,
        'denial-of-service': 1,
        'injection': 1,
        'infiltration': 1,
        'botnet': 1,
        'normal': 0
    }

    y = np.array([labels[value] for value in y])
    return y


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


def drop_invalid_rows(x):
    """The CIC 2018 dataset network flow data has invalid rows which are a duplicate of the csv headers - drop them!"""
    return x[x.Timestamp != 'Timestamp']


def process_csv(filepath):
    """Ingest the raw csv data and run pre-processing tasks"""

    log.info('Opening {}...'.format(filepath))

    # NOTE: we cannot use dtype & converters so we convert the columns manually later
    data = dd.read_csv(filepath, blocksize=config.blocksize, assume_missing=True,
                       na_values=['  ', '\r\t', '\t', '', 'nan'])

    # x = drop_invalid_rows(data)
    data = drop_infinity(data)
    data = drop_nan(data)

    # convert pandas series back into dask dataframe
    y = process_labels(data.Label)

    # NOTE: comment to use all columns (if memory limitation isn't problematic)
    x = get_columns(data, best_30)

    # x.visualize(filename='./images/dask-graph1.png')

    x = add_pair_frequency(x, ['Dst Port', 'Protocol'], 'DstPort-protocol pair')
    # x = add_pair_frequency(x, ['Src Port', 'Protocol'], 'SrcPort-Protocol pair')

    # x.Timestamp = x.Timestamp.apply(date_to_timestamp, meta=float)

    # x['Src IP'] = x['Src IP'].apply(convert_ip_address_to_decimal, meta=int)
    # x['Dst IP'] = x['Dst IP'].apply(convert_ip_address_to_decimal, meta=int)

    # x = x.astype(dtype=csv_dtypes)

    # NOTE: only do this if using add_pair_frequency
    # This resolves the "Mismatched divisions" error in train_test_split due to x also being converted to pandas and back to dask
    partitions = y.npartitions
    y = dd.from_pandas(y.compute(), npartitions=partitions)

    x.visualize(filename='./images/dask-graph2.png')
    # dask.visualize(filname='./images/dask-graph.png')

    return x, y


def process_parquet(filepath):
    """Ingest the parquet data and run pre-processing tasks"""

    log.info('Opening {}...'.format(filepath))

    # NOTE: we cannot use dtype & converters so we convert the columns manually later
    data = dd.read_parquet(filepath, blocksize=config.blocksize, assume_missing=True,
                           na_values=['  ', '\r\t', '\t', '', 'nan'])

    # x = drop_invalid_rows(data)
    data = drop_infinity(data)
    data = drop_nan(data)

    # convert pandas series back into dask dataframe
    y = process_labels(data.Label)

    # NOTE: comment to use all columns (if memory limitation isn't problematic)
    x = get_columns(data, best_30)

    x = add_pair_frequency(x, ['Dst Port', 'Protocol'], 'DstPort-protocol pair')
    # x = add_pair_frequency(x, ['Src Port', 'Protocol'], 'SrcPort-Protocol pair')

    # x.Timestamp = x.Timestamp.apply(date_to_timestamp, meta=float)

    # x['Src IP'] = x['Src IP'].apply(convert_ip_address_to_decimal, meta=int)
    # x['Dst IP'] = x['Dst IP'].apply(convert_ip_address_to_decimal, meta=int)

    # x = x.astype(dtype=csv_dtypes)

    # NOTE: only do this if using add_pair_frequency
    # This resolves the "Mismatched divisions" error in train_test_split due to x also being converted to pandas and back to dask
    partitions = y.npartitions
    y = dd.from_pandas(y.compute(), npartitions=partitions)

    return x, y


def add_pair_frequency(x, pair, column_name):
    # note type: dask.Series
    partitions = x.npartitions
    x = x.compute()
    x[column_name] = x.groupby(pair)[pair[0]].transform('count')
    # x = dd.from_pandas(x, npartitions=partitions)
    x = dd.from_pandas(x, npartitions=partitions)

    return x


def get_columns(x, columns):
    """Note: This also drops the Label & Flow ID columns"""
    columns_to_drop = []
    for column in x.columns:
        if column not in columns:
            columns_to_drop.append(column)

    x = x.drop(labels=columns_to_drop, axis=1)
    return x


def process_pcap(filepath):
    """Ingest the raw pcap data and run pre-processing tasks"""

    log.info('Opening {}...'.format(filepath))

    # find file
    if not os.path.isfile(filepath):
        log.info('File {file} does not exist'.format(file=filepath))
        raise Exception()

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

    # NOTE don't use dtypes for pcaps
    data = dd.read_table(tshark_filepath, blocksize=config.blocksize,
                         assume_missing=True, na_values=['  ', '\r\t', '\t', '', 'nan'])

    x = replace_nan(data)
    x = process_addresses(x)

    # drop timestamp and address columns
    x = get_columns(x, tsv_columns)

    # x = x.astype(dtype=pcap_dtypes)

    # NOTE: comment out to disable additional statistical features from Kitsune
    # x = feature_engineering(x)

    return x


def feature_engineering(x):
    """Add features based on network statistics"""
    maxHost = 255
    maxSess = 255
    netStats = NetworkStatistics(np.nan, maxHost, maxSess)

    x.compute().apply(lambda row: feature_stats(row, netStats))

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
