#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.model_selection import cross_val_score
from sklearn.metrics import mean_squared_error
from sklearn.preprocessing import StandardScaler
import numpy as np
import pandas as pd
import argparse
import os
import sys
import matplotlib.pyplot as plt

# logging
import logging as log
log.basicConfig(format='%(asctime)s.%(msecs)06d: %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S', level=log.INFO)

# TODO tune the model by testing different hyperparameters
def train(data):
    x = data

    # split dataset into train & test
    # TODO test stratification
    x_train, x_test = train_test_split(
        x, train_size=0.5, test_size=0.5, shuffle=False)

    log.info(x_train.shape)
    log.info(x_test.shape)

    # TODO test bootstrapping
    iforest = IsolationForest(contamination=0.38, verbose=1)
    x_pred_train = iforest.fit_predict(x_train)
    x_pred_test = iforest.fit_predict(x_test)
    log.info(x_pred_train.shape)
    log.info(np.unique(x_pred_train, return_counts=True))
    log.info(x_pred_test.shape)
    log.info(np.unique(x_pred_test, return_counts=True))


def process_data(filepath):
    log.info('Opening {}...'.format(filepath))
    raw_data = pd.read_csv(filepath)
    
    raw_data = raw_data.drop(['Label'], axis=1)

    # TODO convert timestamp to unix timestamp
    raw_data = raw_data.drop(['Timestamp'], axis=1)

    # find columns with NaN value and replace with 0
    # Flow Byts/s
    nan_columns = raw_data.loc[:, raw_data.isna().any()].columns
    for column in nan_columns:
        raw_data[column].fillna(0, inplace=True)

    # find columns with Infinity value and replace with 0
    # Flow Byts/s
    # Flow Pkts/s
    inf_columns = raw_data.columns.to_series()[np.isinf(raw_data).any()]
    for column in inf_columns:
        # replace Infinity with column max
        inf = raw_data.loc[raw_data[column] != np.inf, column].max()
        raw_data[column].replace(np.inf, inf, inplace=True)

    # find columns with constant values and drop
    # Bwd PSH Flags
    # Fwd URG Flags
    # Bwd URG Flags
    # CWE Flag Count
    # Fwd Byts/b Avg
    # Fwd Pkts/b Avg
    # Fwd Blk Rate Avg
    # Bwd Byts/b Avg
    # Bwd Pkts/b Avg
    # Bwd Blk Rate Avg
    for column in raw_data.columns:
        if len(raw_data[column].value_counts()) == 1:
            raw_data = raw_data.drop([column], axis=1)

    log.info(raw_data.head())

    return raw_data


def parse_args():
    parser = argparse.ArgumentParser(description='Anomanly-based Network Intrusion Detection')
    parser.add_argument('--data', help='.csv file to read flow data from', required=True)
    return parser.parse_args()


# >>> data['Label'].value_counts()
# Benign    762384
# Bot       286191
# Total of 37.54% malicious packets...
if __name__ == '__main__':
    args = parse_args()
    raw_data = process_data(args.data)
    train(raw_data)
