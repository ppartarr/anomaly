#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

import argparse
import glob
import pandas as pd
import logging as log


def stats(data_dir_path):
    """Get statistics from the dataset
    Currently gathering unique labels per day and the % of malicious flows"""
    total_rows = 0
    total_anom = 0
    total_benign = 0
    files = glob.glob(data_dir_path + '/' + '*.csv')

    for file in files:
        benign = 0
        anom = 0
        rows = 0
        unique_labels = set()
        FIN_flags = 0
        RST_flags = 0

        chunks = pd.read_csv(file, chunksize=500000)
        for chunk in chunks:

            benign += chunk['Label'].value_counts()['Benign']
            anom += len(chunk) - chunk['Label'].value_counts()['Benign']
            rows += len(chunk)

            RST_flags += len(chunk[chunk['RST Flag Cnt'] == 1])
            FIN_flags += len(chunk[chunk['FIN Flag Cnt'] == 1])

            total_rows += rows
            total_benign += benign
            total_anom += anom

            unique_labels = unique_labels.union(set(chunk['Label'].unique()))

        # log.info('benign: {b}'.format(b=benign))
        # log.info('anom: {a}'.format(a=anom))
        # log.info('rows: {r}'.format(r=rows))
        log.info('{file} percentage of malicious flows: {percentage}'.format(
            file=file, percentage=100*(anom/(benign + anom))))
        log.info('unique labels: {unique_labels}'.format(unique_labels=unique_labels))

        log.info('number of FIN flags: {f}'.format(f=FIN_flags))
        log.info('number of RST flags: {r}'.format(r=RST_flags))

    log.info('total percentage of malicious flows: {percentage}'.format(
        percentage=100*(total_anom/(total_benign + total_benign))))


def parse_args():
    parser = argparse.ArgumentParser(description='Anomaly-based Network Intrusion Detection')
    parser.add_argument('--dir', default='/data', help='directory containing the network flow csvs', required=True)
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
    stats(args.dir)
