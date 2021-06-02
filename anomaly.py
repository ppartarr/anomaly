#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.model_selection import cross_val_score
from sklearn.model_selection import GridSearchCV
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


def train(x, y):

    # split dataset into train & test
    # TODO test stratification
    x_train, x_test, y_train, y_test = train_test_split(
        x, y, train_size=0.5, test_size=0.5, shuffle=False)

    log.info(x_train.shape)
    log.info(x_test.shape)

    # model_tuning(x_train, y_train)

    # TODO test bootstrapping
    iforest = IsolationForest(n_estimators=80,
        max_features=30,
        verbose=2)

    x_pred_train = iforest.fit_predict(x_train,)
    x_pred_test = iforest.fit_predict(x_test)
    log.info(x_pred_train.shape)
    log.info(np.unique(x_pred_train, return_counts=True))
    log.info(x_pred_test.shape)
    log.info(np.unique(x_pred_test, return_counts=True))


""" Tune the model by testing various hyperparameters using the GridSearchCV
"""
def model_tuning(x_train, y_train):
    iforest = IsolationForest(verbose=1)

    param_grid = {'n_estimators': [40, 60, 80],
        'max_samples': ['auto'],
        'contamination': ['auto'],
        'max_features': [20, 30],
        'bootstrap': [False],
        'n_jobs': [-1]}

    grid_search = GridSearchCV(iforest,
        param_grid,
        scoring="neg_mean_squared_error",
        refit=True,
        return_train_score=True,
        verbose=1)

    # TODO use labels to do supervised learning
    best_model = grid_search.fit(x_train, y_train)

    print('Best parameters', best_model.best_params_)


def process_data(filepath):
    log.info('Opening {}...'.format(filepath))
    raw_data = pd.read_csv(filepath)
    
    y = raw_data['Label']
    y.replace('Bot', -1, inplace=True)
    y.replace('Benign', 1, inplace=True)

    x = raw_data.drop(['Label'], axis=1)

    # TODO convert timestamp to unix timestamp
    x = x.drop(['Timestamp'], axis=1)

    # find columns with NaN value and replace with 0
    # Flow Byts/s
    nan_columns = x.loc[:, x.isna().any()].columns
    for column in nan_columns:
        x[column].fillna(0, inplace=True)

    # find columns with Infinity value and replace with 0
    # Flow Byts/s
    # Flow Pkts/s
    inf_columns = x.columns.to_series()[np.isinf(x).any()]
    for column in inf_columns:
        # replace Infinity with column max
        inf = x.loc[x[column] != np.inf, column].max()
        x[column].replace(np.inf, inf, inplace=True)

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
    for column in x.columns:
        if len(x[column].value_counts()) == 1:
            x = x.drop([column], axis=1)

    log.info(x.head())

    return x, y


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
    x, y = process_data(args.data)
    train(x, y)
