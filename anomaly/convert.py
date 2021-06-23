#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

import argparse
import glob
import pandas as pd
import anomaly.config as config
import logging as log
import dask.dataframe as dd
import os
from anomaly.utils import drop_infinity, drop_nan

dtype = {'ACK Flag Cnt': 'object',
         'Active Max': 'object',
         'Active Mean': 'object',
         'Active Min': 'object',
         'Active Std': 'object',
         'Bwd Blk Rate Avg': 'object',
         'Bwd Byts/b Avg': 'object',
         'Bwd Header Len': 'object',
         'Bwd IAT Max': 'object',
         'Bwd IAT Mean': 'object',
         'Bwd IAT Min': 'object',
         'Bwd IAT Std': 'object',
         'Bwd IAT Tot': 'object',
         'Bwd PSH Flags': 'object',
         'Bwd Pkt Len Max': 'object',
         'Bwd Pkt Len Mean': 'object',
         'Bwd Pkt Len Min': 'object',
         'Bwd Pkt Len Std': 'object',
         'Bwd Pkts/b Avg': 'object',
         'Bwd Pkts/s': 'object',
         'Bwd Seg Size Avg': 'object',
         'Bwd URG Flags': 'object',
         'CWE Flag Count': 'object',
         'Down/Up Ratio': 'object',
         'Dst Port': 'object',
         'ECE Flag Cnt': 'object',
         'FIN Flag Cnt': 'object',
         'Flow Byts/s': 'object',
         'Flow Duration': 'object',
         'Flow IAT Max': 'object',
         'Flow IAT Mean': 'object',
         'Flow IAT Min': 'object',
         'Flow IAT Std': 'object',
         'Flow Pkts/s': 'object',
         'Fwd Act Data Pkts': 'object',
         'Fwd Blk Rate Avg': 'object',
         'Fwd Byts/b Avg': 'object',
         'Fwd Header Len': 'object',
         'Fwd IAT Max': 'object',
         'Fwd IAT Mean': 'object',
         'Fwd IAT Min': 'object',
         'Fwd IAT Std': 'object',
         'Fwd IAT Tot': 'object',
         'Fwd PSH Flags': 'object',
         'Fwd Pkt Len Max': 'object',
         'Fwd Pkt Len Mean': 'object',
         'Fwd Pkt Len Min': 'object',
         'Fwd Pkt Len Std': 'object',
         'Fwd Pkts/b Avg': 'object',
         'Fwd Pkts/s': 'object',
         'Fwd Seg Size Avg': 'object',
         'Fwd Seg Size Min': 'object',
         'Fwd URG Flags': 'object',
         'Idle Max': 'object',
         'Idle Mean': 'object',
         'Idle Min': 'object',
         'Idle Std': 'object',
         'Init Bwd Win Byts': 'object',
         'Init Fwd Win Byts': 'object',
         'PSH Flag Cnt': 'object',
         'Pkt Len Max': 'object',
         'Pkt Len Mean': 'object',
         'Pkt Len Min': 'object',
         'Pkt Len Std': 'object',
         'Pkt Len Var': 'object',
         'Pkt Size Avg': 'object',
         'Protocol': 'object',
         'RST Flag Cnt': 'object',
         'SYN Flag Cnt': 'object',
         'Src Port': 'object',
         'Subflow Bwd Byts': 'object',
         'Subflow Bwd Pkts': 'object',
         'Subflow Fwd Byts': 'object',
         'Subflow Fwd Pkts': 'object',
         'Tot Bwd Pkts': 'object',
         'Tot Fwd Pkts': 'object',
         'TotLen Bwd Pkts': 'object',
         'TotLen Fwd Pkts': 'object',
         'URG Flag Cnt': 'object'}


def convert(args):
    """Converts CSVs to Parquet"""
    if args.csv:
        log.info('Converting file {f} to parquet'.format(f=args.csv))
        data = dd.read_csv(args.csv, blocksize=config.blocksize, assume_missing=True, dtype=dtype,
                           na_values=['  ', '\r\t', '\t', '', 'nan'])
        data = drop_infinity(data)
        data = drop_nan(data)
        dd.to_parquet(df=data, path=args.out + os.path.sep + args.csv + '.parquet')
    elif args.dir:
        files = glob.glob(args.dir + '/' + '*.csv')
        for file in files:
            log.info('Converting file {f} to parquet'.format(f=file))
            file_name = file.split('/')[-1]
            data = dd.read_csv(file, blocksize=config.blocksize, assume_missing=True, dtype=dtype,
                               na_values=['  ', '\r\t', '\t', '', 'nan'])
            data = drop_infinity(data)
            data = drop_nan(data)
            dd.to_parquet(df=data, path=args.out + os.path.sep + file_name + '.parquet')


def parse_args():
    parser = argparse.ArgumentParser(description='Anomaly-based Network Intrusion Detection')
    parser.add_argument('--dir', default='/data', help='directory containing the network flow csvs')
    parser.add_argument('--csv', help='csv file containing network flow csvs')
    parser.add_argument('--out', default='.', help='output directory')
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    convert(args)
