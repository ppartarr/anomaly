
import logging as log
import pandas as pd
import anomaly.config as config

from anomaly.utils import convert_ip_address_to_decimal, date_to_timestamp, drop_infinity, drop_nan, get_columns
from anomaly.columns import best_30, all_columns
from sklearn.preprocessing import LabelEncoder


def process_label(y):
    """Convert a label into a numerical values"""

    # set all malicious labels to -1
    # label names obtained from stats.py
    malicious = {
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
        'Infilteration': -1
    }

    if y in malicious:
        return -1
    elif y == 'Benign':
        return 1
    else:
        log.error('network flow label does not exist: {l}'.format(l=y))
        return 0


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


def process_netcap_labels(y, _):
    """Convert the labels into numerical values"""

    malicious = {
        'bruteforce': 1,
        'denial-of-service': 1,
        'injection': 1,
        'infiltration': 1,
        'botnet': 1,
        'normal': 0
    }

    y = y.replace(to_replace=malicious, inplace=True)
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

        x = chunk
        x = drop_infinity(x)
        x = drop_nan(x)
        # x = drop_constant_columns(x)

        y = process_labels(x.Label)
        x = get_columns(x, all_columns)

        # x.Timestamp = x.Timestamp.apply(date_to_timestamp)
        # x['Flow ID'] = x['Flow ID'].astype('category').cat.codes
        # x['Src IP'] = x['Src IP'].apply(convert_ip_address_to_decimal)
        # x['Dst IP'] = x['Dst IP'].apply(convert_ip_address_to_decimal)
        # x = x.astype(dtype=csv_dtypes)

        x = add_pair_frequency_pandas(x, ['Dst Port', 'Protocol'], ['DstPort-Protocol pair'])

        x_list.append(x)
        y_list.append(y)

    return pd.concat(x_list), pd.concat(y_list)


def process_connection_csv(filepath):
    """Ingest the raw csv data and run pre-processing tasks"""

    log.info('Opening {}...'.format(filepath))

    # NOTE: we cannot use dtype & converters so we convert the columns manually later
    chunks = pd.read_csv(filepath, chunksize=config.chunksize, na_values=['  ', '\r\t', '\t', '', 'nan'])

    x_list = []
    y_list = []

    for chunk in chunks:

        x = chunk

        for column_name in x.columns:
            encoders[column_name](x, column_name)

        x = add_pair_frequency_pandas(x, ['DstPort', 'ApplicationProto'], ['DstPort-Protocol pair'])
        x = drop_infinity(x)
        x = drop_nan(x)

        y = x.Category

        x_list.append(x)
        y_list.append(y)

    log.info(x)
    log.info(y)

    return pd.concat(x_list), pd.concat(y_list)


def add_pair_frequency_pandas(x, pair, column_name):
    x[column_name] = x.groupby(pair)[pair[0]].transform('count')
    return x


def encode_numeric_zscore(df, name, mean=None, sd=None):
    """
    Encodes a numeric column as zscores.
    """
    # replace missing values (NaN) with a 0
    df[name].fillna(0, inplace=True)
    # log.info("encode_numeric_zscore {name}".format(name=name))
    if mean is None:
        mean = df[name].mean()

    if sd is None:
        sd = df[name].std()

    df[name] = (df[name] - mean) / sd
    return df


def encode_string(df, name):
    """
    Encodes text values to indexes(i.e. [1],[2],[3] for red,green,blue).
    """
    # replace missing values (NaN) with an empty string
    df[name].fillna('', inplace=True)
    # log.info("encode_string {name}".format(name=name))
    le = LabelEncoder()
    # explicitly type cast to string
    # to avoid any numbers that slipped in to break the code by simply treating them as strings
    df[name] = le.fit_transform(df[name].astype(str))
    return df


encoders = {
    # Flow / Connection
    'TimestampFirst': encode_numeric_zscore,
    'LinkProto': encode_string,
    'NetworkProto': encode_string,
    'TransportProto': encode_string,
    'ApplicationProto': encode_string,
    'SrcMAC': encode_string,
    'DstMAC': encode_string,
    'SrcIP': encode_string,
    'SrcPort': encode_numeric_zscore,
    'DstIP': encode_string,
    'DstPort': encode_numeric_zscore,
    'Size': encode_numeric_zscore,
    'AppPayloadSize': encode_numeric_zscore,
    'NumPackets': encode_numeric_zscore,
    'UID': encode_string,
    'Duration': encode_numeric_zscore,
    'TimestampLast': encode_numeric_zscore,
    'BytesClientToServer': encode_numeric_zscore,
    'BytesServerToClient': encode_numeric_zscore,
    'TotalSize': encode_numeric_zscore,
    'Category': process_netcap_labels,
}
