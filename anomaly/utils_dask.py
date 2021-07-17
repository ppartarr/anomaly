
import dask.dataframe as dd
import anomaly.config as config
import os
import logging as log
from anomaly.columns import best_30, tsv_columns
from anomaly.utils import convert_ip_address_to_decimal, date_to_timestamp, drop_infinity, drop_nan, get_columns, get_tshark_path, pcap2tsv_with_tshark, process_addresses


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


def replace_nan(x):
    """Replace all the NaN values with -1"""
    log.info('Processing NaN values...')
    return x.fillna(-1)


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

    # x = add_pair_frequency(x, ['Dst Port', 'Protocol'], 'DstPort-protocol pair')
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

    return x, y


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


def add_pair_frequency(x, pair, column_name):
    # note type: dask.Series
    partitions = x.npartitions
    x = x.compute()
    x[column_name] = x.groupby(pair)[pair[0]].transform('count')
    # x = dd.from_pandas(x, npartitions=partitions)
    x = dd.from_pandas(x, npartitions=partitions)

    return x
