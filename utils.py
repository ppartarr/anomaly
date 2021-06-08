#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

from sklearn.preprocessing import StandardScaler
from sklearn.feature_selection import SelectKBest
from sklearn.impute import SimpleImputer
from sklearn.metrics import roc_auc_score, f1_score
from pandas.api.types import is_numeric_dtype, is_string_dtype

import numpy as np
import pandas as pd
import argparse
import matplotlib.pyplot as plt
import logging as log
import os
import subprocess
import csv
import sys
import netaddr

log.basicConfig(format='%(asctime)s.%(msecs)06d: %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S', level=log.INFO)


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


def process_csv(filepath):
    """Ingest the raw csv data and run pre-processing tasks"""

    log.info('Opening {}...'.format(filepath))
    raw_data = pd.read_csv(filepath)

    y = process_labels(raw_data['Label'])

    # x = raw_data.drop(['Timestamp'], axis=1)
    raw_data['Timestamp'] = raw_data['Timestamp'].apply(date_to_timestamp)
    raw_data.drop(['Label'], axis=1, inplace=True)

    x = raw_data
    x = process_infinity(x)
    x = process_nan(x)

    # NOTE: don't drop columns when reading from multiple files since value might vary across files
    # x = drop_constant_columns(x)

    return x, y


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

    # open readers
    raw_data = pd.read_table(tshark_filepath)

    # y = process_labels(raw_data['Label'])

    # x = raw_data.drop(['Timestamp'], axis=1)
    # raw_data['Timestamp'] = raw_data['Timestamp'].apply(date_to_timestamp)

    x = raw_data
    # x = process_infinity(x)
    x = process_nan(x)

    # x['eth.src'].fillna(-1, inplace=True)
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

    # NOTE: don't drop columns when reading from multiple files since value might vary across files
    x = drop_constant_columns(x)

    return x, None


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
    cmd =  '"' + tshark + '" -r '+ filepath +' -T fields '+ fields +' -E header=y -E occurrence=f > '+filepath+".tsv"
    subprocess.call(cmd,shell=True)
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
        # return struct.unpack('!L', socket.inet_aton(str(ipv4_addr)))[0]
        return int(netaddr.IPAddress(ipv4_addr))


def ipv6_to_decimal(ipv6_addr):
    # print(ipv6_addr)
    if ipv6_addr == -1:
        return ipv6_addr
    else:
        # return struct.unpack('!L', socket.inet_aton(str(ipv6_addr)))[0]
        return int(netaddr.IPAddress(ipv6_addr))