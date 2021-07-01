#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

import argparse
import glob
import pandas as pd
import logging as log
import matplotlib.dates as md
import os

from matplotlib import pyplot as plt
from datetime import datetime


def plot(file):
    """Get statistics from the dataset
    Currently gathering unique labels per day and the % of malicious flows"""

    file_name = './images/plots/{file}-FlowBytes.png'.format(file=os.path.basename(file))
    data = []

    chunks = pd.read_csv(file, chunksize=500000)
    for chunk in chunks:
        log.info('opening a new chunk')
        chunk = drop_invalid_rows(chunk)
        data.append(chunk)

    data = pd.concat(data)

    x = data.Timestamp.apply(convert_datestring)
    y = data['Flow Byts/s']

    log.info(x)
    log.info(y)

    plt.figure(figsize=(10, 5))
    fig = plt.scatter(
        x,
        y,
        s=0.1,
        cmap='RdYlGn')
    plt.title("Flow Bytes")
    plt.ylabel("Flow Bytes")
    plt.xlabel("Time")
    plt.xticks(rotation=25)
    plt.subplots_adjust(bottom=0.2)

    ax = plt.gca()
    xfmt = md.DateFormatter('%d/%m/%Y %H:%M:%S')
    ax.xaxis.set_major_formatter(xfmt)

    plt.savefig(file_name)
    log.info('Saved plot as {plt}'.format(plt=file_name))
    plt.show()


def drop_invalid_rows(x):
    """The CIC 2018 dataset network flow data has invalid rows which are a duplicate of the csv headers - drop them!"""
    return x[x.Timestamp != 'Timestamp']


def convert_datestring(x):
    return datetime.strptime(x, '%d/%m/%Y %H:%M:%S')


def parse_args():
    parser = argparse.ArgumentParser(description='Anomaly-based Network Intrusion Detection')
    parser.add_argument('--csv', help='csv containing the network flow csvs', required=True)
    return parser.parse_args()


if __name__ == '__main__':
    # logger config
    log.basicConfig(format='%(asctime)s.%(msecs)06d: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    handlers=[
                        log.FileHandler("anomaly.log"),
                        log.StreamHandler()
                    ],
                    level=log.INFO)
    args = parse_args()
    plot(args.csv)
