#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

import argparse
import glob
import pandas as pd


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
        unique_labels = set()

        chunks = pd.read_csv(file, chunksize=500000)
        for chunk in chunks:

            benign += chunk['Label'].value_counts()['Benign']
            anom += len(chunk) - benign

            total_rows += len(chunk)
            total_benign += benign
            total_anom += anom

            unique_labels = unique_labels.union(set(chunk['Label'].unique()))

        print('{file} percentage of malicious flows: {percentage}'.format(
            file=file, percentage=100*(anom/(benign + anom))))
        print('unique labels: {unique_labels}'.format(unique_labels=unique_labels))

    print('total percentage of malicious flows: {percentage}'.format(
        percentage=100*(total_anom/(total_benign + total_benign))))
    print('unique labels: {unique}'.format(unique=unique_labels))


def parse_args():
    parser = argparse.ArgumentParser(description='Anomanly-based Network Intrusion Detection')
    parser.add_argument('--dir', default='/data', help='directory containing the network flow csvs', required=True)
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    stats(args.dir)
