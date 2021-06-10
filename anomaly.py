#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.metrics import roc_auc_score, plot_roc_curve
from sklearn.preprocessing import StandardScaler
from sklearn.feature_selection import SelectKBest
from sklearn.mixture import GaussianMixture
from datetime import datetime
from functools import reduce

# from models.mondrian_forest import train_mondrian, train_mondrian_without_labels
from models.isolation_forest import train_iforest, train_iforest_without_labels, tune_iforest
from models.gradient_boost import train_gboost
from models.gaussian_mixture import train_gmm, tune_gmm
from models.kitsune import Kitsune
from utils import process_csv, process_pcap

import numpy as np
import pandas as pd
import argparse
import os
import sys
import time
import glob
import matplotlib.pyplot as plt
import logging as log


def train(x, y):
    """Train a model and calculate performance metrics"""
    # split dataset into train & test
    if not y.empty:
        x_train, x_test, y_train, y_test = train_test_split(
            x, y, test_size=0.2, shuffle=False)

        # print(find_best_features(x, x_train, y_train))
        # tune_iforest(x_train, y_train)

        # gmm_tuning(x_train, y_train)

        train_iforest(x, y, x_train, x_test, y_train, y_test)
        # train_gmm(x, y, x_train, x_test, y_train, y_test)
        train_gboost(x, y, x_train, x_test, y_train, y_test)
        # train_mondrian(x, y, x_train, x_test, y_train, y_test)
    else:
        x_train, x_test = train_test_split(
            x, test_size=0.2, shuffle=False)

        train_iforest_without_labels(x, x_train, x_test)


def plot(x, y, guesses, col_name):
    anomaly_indices = np.where(guesses == -1)
    plt.scatter(x[:, 0], x[:, 1])
    plt.scatter(x[anomaly_indices, 0], x[anomaly_indices, 1], edgecolors='r')
    plt.show()


def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Anomaly-based Network Intrusion Detection')
    # NOTE: args for batch models
    parser.add_argument('--csv', help='csv file to read network flow data from')
    parser.add_argument('--dir', help='directory to read csv network flow data from')
    parser.add_argument('--pcap', help='pcap file to read data from')
    # NOTE: args for online models
    parser.add_argument('--connection', help='Connection audit record file (netcap)')
    parser.add_argument('--socket', action='store_true', help='read the data from a unix socket instead of a file')
    return parser.parse_args()


def validate_args(args):
    if (args.csv and args.dir and args.pcap and args.audit):
        log.error('Only on of --csv or --dir or --pcap or --audit can be specified!')
        raise Exception()


def main():
    # logger config
    log.basicConfig(format='%(asctime)s.%(msecs)06d: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    handlers=[
                        log.FileHandler("logs/anomaly.log"),
                        log.StreamHandler()
                    ],
                    level=log.INFO)

    start_time = datetime.now()

    args = parse_args()
    validate_args(args)

    # NOTE: batch training methods
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
        x = process_pcap(args.pcap)
        train(x, pd.DataFrame())

    if args.connection:
        packet_limit = 10000  # the max number of data points to process
        max_autoencoders = 10  # max size for any autoencoder
        feature_mapping_training_samples = 5000  # number of instances taken to learn the feature mapping
        anomaly_detector_training_samples = 500000  # the number of instances taken to train the ensemble
        # feature_extractor =
        if args.socket:
            detector = Kitsune(None,
                               args.connection,
                               packet_limit,
                               max_autoencoders,
                               feature_mapping_training_samples,
                               anomaly_detector_training_samples,

                               )
        else:
            detector = Kitsune(args.connection,
                               None,
                               packet_limit,
                               max_autoencoders,
                               feature_mapping_training_samples,
                               anomaly_detector_training_samples)
        detector.run()

    end_time = datetime.now()
    print('Execution time: {time}'.format(time=(end_time - start_time)))


if __name__ == '__main__':
    main()
