#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.metrics import roc_auc_score, plot_roc_curve
from sklearn.preprocessing import StandardScaler
from sklearn.feature_selection import SelectKBest
from sklearn.mixture import GaussianMixture
from models.isolation_forest import train_iforest, train_iforest_without_labels, tune_iforest
from models.gradient_boost import train_gboost
from models.gaussian_mixture import train_gmm, tune_gmm
from utils import process_csv, process_pcap
from datetime import datetime
from functools import reduce

import numpy as np
import pandas as pd
import argparse
import os
import sys
import time
import glob
import matplotlib.pyplot as plt

# logging
import logging as log
log.basicConfig(format='%(asctime)s.%(msecs)06d: %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S', level=log.INFO)


def train(x, y):
    """Train the model and calculate performance metrics"""
    # split dataset into train & test
    if y != None:
        x_train, x_test, y_train, y_test = train_test_split(
            x, y, test_size=0.2, shuffle=False)

        # print(find_best_features(x, x_train, y_train))
        # tune_iforest(x_train, y_train)

        # gmm_tuning(x_train, y_train)

        train_iforest(x, y, x_train, x_test, y_train, y_test)
        # train_gmm(x, y, x_train, x_test, y_train, y_test)
        # train_gboost(x, y, x_train, x_test, y_train, y_test)
    else:
        x_train, x_test = train_test_split(
            x, test_size=0.2, shuffle=False)

        train_iforest_without_labels(x, x_train, x_test)


def plot(x, y, guesses, col_name):
    anomaly_indices = np.where(guesses == -1)
    plt.scatter(x[:,0], x[:,1])
    plt.scatter(x[anomaly_indices,0], x[anomaly_indices,1], edgecolors='r')
    plt.show()


def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Anomaly-based Network Intrusion Detection')
    parser.add_argument('--csv', help='csv file to read network flow data from')
    parser.add_argument('--dir', help='directory to read csv network flow data from')
    parser.add_argument('--pcap', help='pcap file to read data from')

    return parser.parse_args()


def validate_args(args):
    if (args.csv and args.dir and args.pcap):
        log.error('Only on of --csv or --dir or --pcap can be specified!')
        raise Exception()


if __name__ == '__main__':
    start_time = datetime.now()

    args = parse_args()
    validate_args(args)

    if args.csv:
        x, y = process_csv(args.csv)
        train(x, y)
    elif args.dir:
        # concatenate the tuples with map reduce
        out = map(process_csv, glob.glob(args.dir + os.path.sep + '*.csv'))
        x, y = reduce(lambda x, y: (
            pd.concat([x[0], y[0]], ignore_index=True),
            pd.concat([x[1], y[1]], ignore_index=True)
        ), out)
        train(x, y)
    elif args.pcap:
        x, y = process_pcap(args.pcap)
        train(x, y)

    end_time = datetime.now()
    print('Execution time: {time}'.format(time=(end_time - start_time)))
