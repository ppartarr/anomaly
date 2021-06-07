#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.metrics import roc_auc_score, plot_roc_curve
from sklearn.preprocessing import StandardScaler
from sklearn.feature_selection import SelectKBest
from sklearn.mixture import GaussianMixture
from model import train_gmm, train_iforest, train_gboost, gmm_tuning, iforest_tuning
from utils import process_data

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
        x, y, test_size=0.2, shuffle=False)

    # print(find_best_features(x, x_train, y_train))
    # model_tuning(x_train, y_train)

    # gmm_tuning(x_train, y_train)

    train_iforest(x, y, x_train, x_test, y_train, y_test)
    # train_gmm(x, y, x_train, x_test, y_train, y_test)
    # train_gboost(x, y, x_train, x_test, y_train, y_test)


def plot(x, y, guesses, col_name):
    anomaly_indices = np.where(guesses == -1)
    plt.scatter(x[:,0], x[:,1])
    plt.scatter(x[anomaly_indices,0], x[anomaly_indices,1], edgecolors='r')
    plt.show()


def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Anomanly-based Network Intrusion Detection')
    parser.add_argument('--data', help='.csv file to read flow data from', required=True)
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    x, y = process_data(args.data)
    train(x, y)
