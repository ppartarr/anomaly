#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

from sklearn.preprocessing import StandardScaler
from sklearn.feature_selection import SelectKBest
from sklearn.impute import SimpleImputer
from sklearn.metrics import roc_auc_score, f1_score
import numpy as np
import pandas as pd
import argparse
import matplotlib.pyplot as plt
import logging as log

log.basicConfig(format='%(asctime)s.%(msecs)06d: %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S', level=log.INFO)


def print_stats(y, guesses, y_test):
    log.info('guess percentage of anomalies: {percentage:.2f}'.format(percentage=(100 * np.count_nonzero(guesses == -1)) / len(guesses)))
    log.info('actual percentage of anomalies: {percentage:.2f}'.format(percentage=(100 - (100 * (y.value_counts()[1])) / len(y))))

    auc = roc_auc_score(y_test, guesses)
    print('area under the curve: {auc}'.format(auc=auc))

    f1 = f1_score(y_test, guesses)
    print('f1 score: {f1}'.format(f1=f1))


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
    # nan_columns = x.loc[:, x.isna().any()].columns
    # for column in nan_columns:
    #     x[column].fillna(0, inplace=True)
    imputer = SimpleImputer(missing_values=np.nan, strategy='mean')
    x = pd.DataFrame(data=imputer.fit_transform(x.values), columns=x.columns)
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