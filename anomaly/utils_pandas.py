
import logging as log
import pandas as pd
import anomaly.config as config

from anomaly.utils import convert_ip_address_to_decimal, date_to_timestamp, drop_infinity, drop_nan, get_columns
from anomaly.columns import best_30


def process_labels(y):
    """Convert the labels into numerical values"""

    log.info('Processing labels...')

    # set all malicious labels to -1
    # label names obtained from stats.py
    labels = {
        'DoS attacks-SlowHTTPTest': -1,
        'DoS attacks-GoldenEye': -1,
        'DoS attacks-Hulk': -1,
        'DoS attacks-Slowloris': -1,
        'DDOS attack-LOIC-UDP': -1,
        'DDoS attacks-LOIC-HTTP': -1,
        'DDOS attack-HOIC': -1,
        'SSH-Bruteforce': -1,
        'Brute Force -Web': -1,
        'Brute Force -XSS': -1,
        'FTP-BruteForce': -1,
        'SQL Injection': -1,
        'Bot': -1,
        'Infilteration': -1,
        'Benign': 1
    }

    y = y.replace(to_replace=labels)
    return y


def drop_constant_columns(x):
    """Remove the columns with constant values"""
    for column in x.columns:
        if len(x[column].value_counts()) == 1:
            x = x.drop([column], axis=1)
    return x


def process_csv(filepath):
    """Ingest the raw csv data and run pre-processing tasks"""

    log.info('Opening {}...'.format(filepath))

    # NOTE: we cannot use dtype & converters so we convert the columns manually later
    chunks = pd.read_csv(filepath, chunksize=config.chunksize, na_values=['  ', '\r\t', '\t', '', 'nan'])

    x_list = []
    y_list = []

    for chunk in chunks:

        y = process_labels(chunk.Label)

        x = chunk
        x = drop_infinity(x)
        x = drop_nan(x)
        x = add_pair_frequency_pandas(x, ['Dst Port', 'Protocol'], ['DstPort-Protocol pair'])
        x = get_columns(x, best_30)

        # x.Timestamp = x.Timestamp.apply(date_to_timestamp)
        # x['Flow ID'] = x['Flow ID'].astype('category').cat.codes
        # x['Src IP'] = x['Src IP'].apply(convert_ip_address_to_decimal)
        # x['Dst IP'] = x['Dst IP'].apply(convert_ip_address_to_decimal)
        # x = x.astype(dtype=csv_dtypes)

        x = drop_constant_columns(x)

        x_list.append(x)
        y_list.append(y)

    return pd.concat(x_list), pd.concat(y_list)


def add_pair_frequency_pandas(x, pair, column_name):
    x[column_name] = x.groupby(pair)[pair[0]].transform('count')
    return x
