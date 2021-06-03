#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.model_selection import cross_val_score
from sklearn.model_selection import GridSearchCV
from sklearn.metrics import roc_auc_score
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer
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
    """Train the model and calculate performance metrics"""
    # split dataset into train & test
    x_train, x_test, y_train, y_test = train_test_split(
        x, y, test_size=0.2, shuffle=True)

    # model_tuning(x_train, y_train)

    iforest = IsolationForest(n_estimators=80,
        max_features=30,
        verbose=1)

    estimator = iforest.fit(x_train)
    guesses = estimator.predict(x_test)

    log.info('guess percentage of anomalies: {percentage:.2f}'.format(percentage=(100 * np.count_nonzero(guesses == -1)) / len(guesses)))
    log.info('actual percentage of anomalies: {percentage:.2f}'.format(percentage=((len(y) - y.value_counts()[1])*100) / y.value_counts()[1]))

    auc = roc_auc_score(y_test, guesses)
    print('area under the curve: {auc}'.format(auc=auc))



def model_tuning(x_train, y_train):
    """ Tune the model by testing various hyperparameters using the GridSearchCV"""

    iforest = IsolationForest(verbose=1)

    param_grid = {'n_estimators': [40, 60, 80],
        'max_samples': ['auto'],
        'contamination': ['auto'],
        'max_features': [20, 30],
        'bootstrap': [False],
        'n_jobs': [-1]}

    grid_search = GridSearchCV(iforest,
        param_grid,
        scoring="roc_auc_score",
        refit=True,
        return_train_score=True,
        verbose=1)

    # TODO use labels to do supervised learning
    best_model = grid_search.fit(x_train, y_train)

    print('Best parameters', best_model.best_params_)


def process_labels(y):
    """Convert the labels into numerical values"""

    # set all malicious labels to -1
    y.replace('Bot', -1, inplace=True)
    y.replace('DoS GoldenEye', -1, inplace=True)
    y.replace('Heartbleed', -1, inplace=True)
    y.replace('DoS Hulk', -1, inplace=True)
    y.replace('DoS Slowhttp', -1, inplace=True)
    y.replace('DoS slowloris', -1, inplace=True)
    y.replace('SSH-Patator', -1, inplace=True)
    y.replace('FTP-Patator', -1, inplace=True)
    y.replace('Web Attack', -1, inplace=True)
    y.replace('Infiltration', -1, inplace=True)
    y.replace('PortScan', -1, inplace=True)
    y.replace('DDoS', -1, inplace=True)

    # set normal label to 1
    y.replace('Benign', 1, inplace=True)

    return y


def process_infinity(x):
    """Replace all the Infinity values with the column's max"""
    inf_columns = x.columns[np.isinf(x).any()]
    for column in inf_columns:
        # replace Infinity with column max
        inf = x.loc[x[column] != np.inf, column].max()
        x[column].replace(np.inf, inf, inplace=True)
    
    return x


def process_nan(x):
    """Replace all the NaN values with the column's median"""
    nan_columns = x.loc[:, x.isna().any()].columns
    for column in nan_columns:
        x[column].fillna(0, inplace=True)
    # imputer = SimpleImputer(missing_values=np.nan, strategy='most_frequent')
    # x = pd.DataFrame(data=imputer.transform(x.values), columns=x.columns)
    return x


def process_data(filepath):
    """Ingest the raw csv data and run pre-processing tasks"""

    log.info('Opening {}...'.format(filepath))
    raw_data = pd.read_csv(filepath)

    y = process_labels(raw_data['Label'])

    # TODO convert timestamp to unix timestamp
    x = raw_data.drop(['Timestamp'], axis=1)

    x.drop(['Label'], axis=1, inplace=True)
    x = process_nan(x)
    x = process_infinity(x)

    # find columns with constant values and drop
    for column in x.columns:
        if len(x[column].value_counts()) == 1:
            x = x.drop([column], axis=1)

    return x, y


def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Anomanly-based Network Intrusion Detection')
    parser.add_argument('--data', help='.csv file to read flow data from', required=True)
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    x, y = process_data(args.data)
    train(x, y)
