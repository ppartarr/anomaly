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
from anomaly.extractors.network_flow import NetworkFlowFeatureExtractor
from anomaly.extractors.audit.connections import ConnectionFeatureExtractor
from anomaly.extractors.audit.arp import ARPFeatureExtractor
from anomaly.extractors.audit.credentials import CredentialsFeatureExtractor
from anomaly.extractors.audit.device_profile import DeviceProfileFeatureExtractor
from anomaly.extractors.audit.dhcpv4 import DHCPv4ProfileFeatureExtractor
from anomaly.extractors.audit.dhcpv6 import DHCPv6ProfileFeatureExtractor
from anomaly.extractors.audit.dns import DNSFeatureExtractor
from anomaly.extractors.audit.ethernet import EthernetFeatureExtractor
from anomaly.extractors.audit.exploit import ExploitFeatureExtractor
from anomaly.extractors.audit.http import HTTPFeatureExtractor
from anomaly.extractors.audit.icmpv4 import ICMPv4FeatureExtractor
from anomaly.extractors.audit.icmpv6 import ICMPv6FeatureExtractor
from anomaly.extractors.audit.igmp import IGMPFeatureExtractor
from anomaly.extractors.audit.ip_profile import IPProfileFeatureExtractor
from anomaly.extractors.audit.ipv4 import IPv4FeatureExtractor
from anomaly.extractors.audit.ipv6_hop_by_hop import IPv6HopByHopFeatureExtractor
from anomaly.extractors.audit.ipv6 import IPv6FeatureExtractor
from anomaly.extractors.audit.ntp import NTPFeatureExtractor
from anomaly.extractors.audit.service import ServiceFeatureExtractor
from anomaly.extractors.audit.sip import SIPFeatureExtractor
from anomaly.extractors.audit.software import SoftwareFeatureExtractor
from anomaly.extractors.audit.tcp import TCPFeatureExtractor
from anomaly.extractors.audit.tls_client_hello import TLSClientHelloFeatureExtractor
from anomaly.extractors.audit.tls_server_hello import TLSServerHelloFeatureExtractor
from anomaly.extractors.audit.udp import UDPFeatureExtractor
from anomaly.extractors.audit.vulnerability import VulnerabilityFeatureExtractor
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
import threading


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

        # log.info(find_best_features(x, x_train, y_train))

        classifier = model(x, y, x_train, x_test, y_train, y_test)
        if tune:
            classifier.tune()

        # handle exceptions so that one failing model doesn't cause failure(when using --offline)
        try:
            start_time = datetime.now()
            classifier.train()
            end_time = datetime.now()
            log.info('Model execution time: {time}'.format(time=(end_time - start_time)))
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
    parser.add_argument('--arp', help='ARP audit record file (netcap)')
    parser.add_argument('--credentials', help='Credentials audit record file (netcap)')
    parser.add_argument('--device', help='Device Profile audit record file (netcap)')
    parser.add_argument('--dhcpv4', help='DHCPv4 audit record file (netcap)')
    parser.add_argument('--dhcpv6', help='DHCPv6 audit record file (netcap)')
    parser.add_argument('--dns', help='DNS audit record file (netcap)')
    parser.add_argument('--ethernet', help='Ethernet audit record file (netcap)')
    parser.add_argument('--exploit', help='Exploit audit record file (netcap)')
    parser.add_argument('--http', help='HTTP audit record file (netcap)')
    parser.add_argument('--icmpv4', help='ICMPv4 audit record file (netcap)')
    parser.add_argument('--icmpv6', help='ICMPv6 audit record file (netcap)')
    parser.add_argument('--igmp', help='IGMP audit record file (netcap)')
    parser.add_argument('--ipprofile', help='IPProfile audit record file (netcap)')
    parser.add_argument('--ipv4', help='IPv4 audit record file (netcap)')
    parser.add_argument('--ipv6hop', help='IPv6HopByHop audit record file (netcap)')
    parser.add_argument('--ipv6', help='IPv6 audit record file (netcap)')
    parser.add_argument('--ntp', help='NTP audit record file (netcap)')
    parser.add_argument('--service', help='Servie audit record file (netcap)')
    parser.add_argument('--sip', help='SIP audit record file (netcap)')
    parser.add_argument('--software', help='Software audit record file (netcap)')
    parser.add_argument('--tcp', help='TCP audit record file (netcap)')
    parser.add_argument('--tls-client-hello', help='TLSClientHello audit record file(netcap)')
    parser.add_argument('--tls-server-hello', help='TLSServerHello audit record file(netcap)')
    parser.add_argument('--udp', help='UDP audit record file (netcap)')
    parser.add_argument('--vulnerability', help='vulnerability audit record file (netcap)')
    parser.add_argument('--audit', help='Read the given audit record types from unix sockets',
                        choices=audit_records, nargs='*')
    parser.add_argument('--encoded', action='store_true', help='Read encoded audit records')
    return parser.parse_args()


def validate_args(args):
    if (args.csv and args.csv_dir and args.pcap):
        raise Exception('Only on of --csv or --dir or --pcap can be specified!')


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

        x, y = get_offline_data(args)

        # run all offline models for comparison
        if args.model == 'offline':
            for model in model_choice[args.model]:
                train(x, y, model, args.tune)

        # run a single offline model
        else:
            train(x, y, model_choice[args.model], args.tune)

    # online training methods
    else:
        reader = get_reader(args)

        if args.audit:
            for audit_record_type in args.audit:
                path = audit_records[audit_record_type]['socket']
                feature_extractor = audit_records[audit_record_type]['feature_extractor']
                threads = []

                # allow experiments on multiple sockets comparing online models
                if args.model == 'online':
                    for model in model_choice[args.model]:
                        # don't run different models in different threads to avoid messy logging
                        detector = build_online_model(args, path, reader, feature_extractor)
                        detector.run()

                else:
                    detector = build_online_model(args, path, reader, feature_extractor)
                    thread = threading.Thread(target=detector.run(), name=model)
                    threads.append(thread)

                for thread in threads:
                    thread.join()
                    log.info('Thread {name} is done'.format(name=thread.name))
        else:
            path = get_path(args)
            feature_extractor = get_feature_extractor(args)
            if args.model == 'online':
                for model in model_choice[args.model]:
                    detector = build_online_model(args, path, reader, feature_extractor)
                    detector.run()
            else:
                detector = build_online_model(args, path, reader, feature_extractor)
                detector.run()

    end_time = datetime.now()
    log.info('Execution time: {time}'.format(time=(end_time - start_time)))


def get_offline_data(args):
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

    return x, y


def build_online_model(args, path, reader, feature_extractor):
    if args.model == 'kitsune':
        detector = Kitsune(
            path=path,
            reader=reader,
            limit=config.auto_encoder['packet_limit'],
            feature_extractor=feature_extractor,
            max_autoencoder_size=config.auto_encoder['max_autoencoders'],
            feature_mapping_training_samples=config.auto_encoder['feature_mapping_training_samples'],
            anomaly_detector_training_samples=config.auto_encoder['anomaly_detector_training_samples'],
            encoded=args.encoded)
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
    return detector


def get_path(args):
    if args.csv:
        path = args.csv
    elif args.pcap:
        # Try convert PCAP file to TSV and use TSV reader if tshark is in path (much faster than scapy)
        if os.path.isfile(args.pcap + '.tsv'):
            log.info('TSV already exists, using tshark')
            path = args.pcap + '.tsv'
        elif os.path.isfile(get_tshark_path()):
            pcap2tsv_with_tshark(args.pcap)  # creates local tsv file
            args.pcap += ".tsv"
            path = args.pcap
        # last resort, use scapy
        else:
            path = args.pcap
    elif args.tsv:
        path = args.tsv
    elif args.conn:
        path = args.conn
    elif args.arp:
        path = args.arp
    elif args.credentials:
        path = args.credentials
    elif args.device:
        path = args.device
    elif args.dhcpv4:
        path = args.dhcpv4
    elif args.dhcpv6:
        path = args.dhcpv6
    elif args.dns:
        path = args.dns
    elif args.ethernet:
        path = args.ethernet
    elif args.exploit:
        path = args.exploit
    elif args.http:
        path = args.http
    elif args.icmpv4:
        path = args.icmpv4
    elif args.icmpv6:
        path = args.icmpv6
    elif args.igmp:
        path = args.igmp
    elif args.ipprofile:
        path = args.ipprofile
    elif args.ipv4:
        path = args.ipv4
    elif args.ipv6hop:
        path = args.ipv6hop
    elif args.ipv6:
        path = args.ipv6
    elif args.ntp:
        path = args.ntp
    elif args.service:
        path = args.service
    elif args.sip:
        path = args.sip
    elif args.software:
        path = args.software
    elif args.tcp:
        path = args.tcp
    elif args.tls_client_hello:
        path = args.tls_client_hello
    elif args.tls_server_hello:
        path = args.tls_server_hello
    elif args.udp:
        path = args.udp
    elif args.vulnerability:
        path = args.vulnerability

    return path


def get_reader(args):
    if args.csv:
        reader = CSVReader
    elif args.pcap:
        if os.path.isfile(args.pcap + '.tsv') or os.path.isfile(get_tshark_path()):
            reader = TSVReader
        # last resort, use scapy
        else:
            reader = PCAPReader
    elif args.tsv:
        reader = TSVReader
    elif args.audit:
        reader = SocketReader
    # reading CSV from audit record
    else:
        reader = CSVReader
    return reader


def get_feature_extractor(args):
    if args.csv:
        feature_extractor = NetworkFlowFeatureExtractor
    elif args.pcap or args.tsv:
        feature_extractor = RawPacketFeatureExtractor
    elif args.conn:
        feature_extractor = ConnectionFeatureExtractor
    elif args.arp:
        feature_extractor = ARPFeatureExtractor
    elif args.credentials:
        feature_extractor = CredentialsFeatureExtractor
    elif args.device:
        feature_extractor = DeviceProfileFeatureExtractor
    elif args.dhcpv4:
        feature_extractor = DHCPv4ProfileFeatureExtractor
    elif args.dhcpv6:
        feature_extractor = DHCPv6ProfileFeatureExtractor
    elif args.dns:
        feature_extractor = DNSFeatureExtractor
    elif args.ethernet:
        feature_extractor = EthernetFeatureExtractor
    elif args.exploit:
        feature_extractor = ExploitFeatureExtractor
    elif args.http:
        feature_extractor = HTTPFeatureExtractor
    elif args.icmpv4:
        feature_extractor = ICMPv4FeatureExtractor
    elif args.icmpv6:
        feature_extractor = ICMPv6FeatureExtractor
    elif args.igmp:
        feature_extractor = IGMPFeatureExtractor
    elif args.ipprofile:
        feature_extractor = IPProfileFeatureExtractor
    elif args.ipv4:
        feature_extractor = IPv4FeatureExtractor
    elif args.ipv6hop:
        feature_extractor = IPv6HopByHopFeatureExtractor
    elif args.ipv6:
        feature_extractor = IPv6FeatureExtractor
    elif args.ntp:
        feature_extractor = NTPFeatureExtractor
    elif args.service:
        feature_extractor = ServiceFeatureExtractor
    elif args.sip:
        feature_extractor = SIPFeatureExtractor
    elif args.software:
        feature_extractor = SoftwareFeatureExtractor
    elif args.tcp:
        feature_extractor = TCPFeatureExtractor
    elif args.tls_client_hello:
        feature_extractor = TLSClientHelloFeatureExtractor
    elif args.tls_server_hello:
        feature_extractor = TLSServerHelloFeatureExtractor
    elif args.udp:
        feature_extractor = UDPFeatureExtractor
    elif args.vulnerability:
        feature_extractor = VulnerabilityFeatureExtractor

    return feature_extractor


if __name__ == '__main__':
    main()
