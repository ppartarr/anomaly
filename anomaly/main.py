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

# from anomaly.models.mondrian_forest import train_mondrian, train_mondrian_without_labels
from anomaly.models.model_choice import model_choice, is_model_online
from anomaly.models.offline.isolation_forest import IForest
from anomaly.models.offline.gradient_boost import GBoost
from anomaly.models.offline.gaussian_mixture import GMix
from anomaly.models.offline.local_outlier_factor import LOF
from anomaly.models.offline.svm import SVM

from anomaly.models.online.half_space_tree import HSTree
from anomaly.models.online.kitsune import Kitsune
from anomaly.models.online.igradient_boost import IGBoost


from anomaly.extractors.raw_packets import RawPacketFeatureExtractor
from anomaly.extractors.connections import ConnectionFeatureExtractor
from anomaly.readers.csv import CSVReader
from anomaly.readers.pcap import PCAPReader
from anomaly.readers.tsv import TSVReader, get_tshark_path, pcap2tsv_with_tshark
from anomaly.readers.socket import SocketReader
from anomaly.utils import process_csv, process_pcap
from anomaly.audit_records import audit_records
from anomaly.models.stats import find_best_features

import anomaly.config as config

import dask.dataframe as dd
from dask.distributed import Client

import numpy as np
import pandas as pd
import argparse
import os
import sys
import time
import glob
import matplotlib.pyplot as plt
import logging as log


def train(x, y, model, tune):
    """Train a model and calculate performance metrics"""

    # convert from dask to pandas if necessary
    x = x.compute() if isinstance(x, dd.DataFrame) else x
    y = y.compute() if isinstance(y, dd.Series) else y

    # for labelled data
    if not y.empty:
        # split dataset into train & test
        x_train, x_test, y_train, y_test = train_test_split(
            x, y, test_size=0.2, shuffle=False)

        # print(find_best_features(x, x_train, y_train))

        classifier = model(x, y, x_train, x_test, y_train, y_test)
        if tune:
            classifier.tune()

        # handle exceptions so that one failing model doesn't cause failure (when using --offline)
        try:
            classifier.train()
        except Exception as e:
            log.error(e)

    # for unlabelled data
    else:
        x_train, x_test = train_test_split(
            x, test_size=0.2, shuffle=False)

        classifier = model(x, y, x_train, x_test, pd.DataFrame(), pd.DataFrame())
        classifier.train()


def plot(x, y, guesses, col_name):
    anomaly_indices = np.where(guesses == -1)
    plt.scatter(x[:, 0], x[:, 1])
    plt.scatter(x[anomaly_indices, 0], x[anomaly_indices, 1], edgecolors='r')
    plt.show()


def parse_args():
    """Parse command line arguments"""
    # TODO default for model, conn, socket
    parser = argparse.ArgumentParser(description='Anomaly-based Network Intrusion Detection')
    parser.add_argument('--model', choices=model_choice.keys(),
                        help='Model to train & use', metavar='model', required=True)  # default=model_choice['Kitsune']
    # NOTE: args for offline models
    parser.add_argument('--csv', help='csv file to read network flow data from')
    parser.add_argument('--csv-dir', help='directory to read csv network flow data from')
    parser.add_argument('--pcap', help='pcap file to read data from')
    parser.add_argument('--pcap-dir', help='directory to read pcaps from')
    parser.add_argument('--tune', action='store_true', help='tune model before training to find best hyperparameters')
    # NOTE: args for online models
    parser.add_argument('--tsv', help='tsv file to read data from')
    parser.add_argument('--conn', help='Connection audit record file (netcap)')  # default='/tmp/Connection.sock'
    parser.add_argument('--socket', action='store_true',
                        help='read the data from a unix socket instead of a file')  # default=True
    parser.add_argument('--audit', help='Read the given audit record types from unix sockets',
                        choices=audit_records, nargs='*')
    return parser.parse_args()


def validate_args(args):
    if (args.csv and args.csv_dir and args.pcap):
        log.error('Only on of --csv or --dir or --pcap can be specified!')
        raise Exception()


def main():
    # logger config
    log.basicConfig(format='%(asctime)s.%(msecs)06d: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    handlers=[
                        log.FileHandler("anomaly.log"),
                        log.StreamHandler()
                    ],
                    level=log.INFO)

    start_time = datetime.now()

    args = parse_args()
    validate_args(args)

    # if model is offline
    if not is_model_online(args.model):

        # start dask dashboard
        client = Client(n_workers=2, threads_per_worker=4, processes=True, memory_limit='4GB')
        log.info('connect to the dask dashboard at {url}'.format(url='http://localhost:8787/status'))

        # compare all offline models
        if args.model == 'offline':
            if args.csv:
                x, y = process_csv(args.csv)
            elif args.csv_dir:
                x, y = process_csv(args.csv_dir + os.path.sep + '*.csv')
            elif args.pcap or args.tsv:
                # NOTE: comment in for pcap offline algs
                x = process_pcap(args.pcap)
                y = pd.DataFrame()
            elif args.pcap_dir:
                # concatenate the tuples with map reduce
                x = process_pcap(args.pcap_dir + os.path.sep + '*.pcap')
                y = pd.DataFrame()

            for model in model_choice[args.model]:
                train(x, y, model, args.tune)

        # run a single offline model
        else:
            if args.csv:
                x, y = process_csv(args.csv)
            elif args.csv_dir:
                x, y = process_csv(args.csv_dir + os.path.sep + '*.csv')
            elif args.pcap or args.tsv:
                # NOTE: comment in for pcap offline algs
                x = process_pcap(args.pcap)
                y = pd.DataFrame()
            elif args.pcap_dir:
                x = process_pcap(args.pcap_dir + os.path.sep + '*.pcap')
                y = pd.DataFrame()

            train(x, y, model_choice[args.model], args.tune)

    # online training methods
    else:
        if args.pcap:
            # Try convert PCAP file to TSV and use TSV reader if tshark is in path (much faster than scapy)
            if os.path.isfile(args.pcap + '.tsv'):
                log.info('TSV already exists, using tshark')
                path = args.pcap + '.tsv'
                reader = TSVReader
            elif os.path.isfile(get_tshark_path()):
                pcap2tsv_with_tshark(args.pcap)  # creates local tsv file
                args.pcap += ".tsv"
                path = args.pcap
                reader = TSVReader
            # last resort, use scapy
            else:
                path = args.pcap
                reader = PCAPReader

            feature_extractor = RawPacketFeatureExtractor
        elif args.tsv:
            path = args.pcap
            reader = TSVReader
            feature_extractor = RawPacketFeatureExtractor
        elif args.conn:
            if args.socket:
                path = args.conn
                reader = SocketReader
            else:
                path = args.conn
                reader = CSVReader

            feature_extractor = ConnectionFeatureExtractor

        if not args.audit:
            if args.model == 'kitsune':
                detector = Kitsune(
                    path=path,
                    reader=reader,
                    limit=config.auto_encoder['packet_limit'],
                    feature_extractor=feature_extractor,
                    max_autoencoder_size=config.auto_encoder['max_autoencoders'],
                    feature_mapping_training_samples=config.auto_encoder['feature_mapping_training_samples'],
                    anomaly_detector_training_samples=config.auto_encoder['anomaly_detector_training_samples'])
            elif args.model == 'hstree':
                detector = HSTree(
                    path=path,
                    reader=reader,
                    limit=config.hstree['packet_limit'],
                    feature_extractor=feature_extractor,
                    anomaly_detector_training_samples=config.hstree['anomaly_detector_training_samples'])
            elif args.model == 'igboost':
                detector = IGBoost(
                    path=path,
                    reader=reader,
                    limit=config.hstree['packet_limit'],
                    feature_extractor=feature_extractor,
                    anomaly_detector_training_samples=config.hstree['anomaly_detector_training_samples'])

            detector.run()

        # running multiple models, one per audit record
        else:
            reader = SocketReader
            for audit_record_type in args.audit:
                if args.model == 'kitsune':
                    detector = Kitsune(
                        path=audit_records[audit_record_type],
                        reader=reader,
                        limit=config.auto_encoder['packet_limit'],
                        feature_extractor=feature_extractor,
                        max_autoencoder_size=config.auto_encoder['max_autoencoders'],
                        feature_mapping_training_samples=config.auto_encoder['feature_mapping_training_samples'],
                        anomaly_detector_training_samples=config.auto_encoder['anomaly_detector_training_samples'])
                elif args.model == 'hstree':
                    detector = HSTree(
                        path=path,
                        reader=reader,
                        limit=config.hstree['packet_limit'],
                        feature_extractor=feature_extractor,
                        anomaly_detector_training_samples=config.hstree['anomaly_detector_training_samples'])
                elif args.model == 'igboost':
                    detector = IGBoost(
                        path=path,
                        reader=reader,
                        limit=config.hstree['packet_limit'],
                        feature_extractor=feature_extractor,
                        anomaly_detector_training_samples=config.hstree['anomaly_detector_training_samples'])

                log.info(detector)
                detector.run()

    end_time = datetime.now()
    print('Execution time: {time}'.format(time=(end_time - start_time)))


if __name__ == '__main__':
    main()
