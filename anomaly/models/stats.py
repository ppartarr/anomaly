#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8
from sklearn.feature_selection import SelectKBest
from sklearn.metrics import roc_auc_score, f1_score
import logging as log
import numpy as np

log = log.getLogger(__name__)


def find_best_features(x, x_train, y_train):
    select = SelectKBest(k=30)
    selected_features = select.fit(x_train, y_train)
    indices_selected = selected_features.get_support(indices=True)
    col_names_selected = [x.columns[i] for i in indices_selected]
    return col_names_selected


def print_stats_labelled(y, guesses, y_test):
    """Statistics for labelled data"""
    log.info('guess percentage of anomalies: {percentage:.2f}'.format(
        percentage=(100 * np.count_nonzero(guesses == -1)) / len(guesses)))
    log.info('actual percentage of anomalies: {percentage:.2f}'.format(
        percentage=(100 - (100 * (y.value_counts()[1])) / len(y))))

    # ROC AUC score is not defined if there is only one class in y_true
    if len(y_test.value_counts()) > 1:
        auc = roc_auc_score(y_test, guesses)
        log.info('area under the curve: {auc}'.format(auc=auc))

    f1 = f1_score(y_test, guesses)
    log.info('f1 score: {f1}'.format(f1=f1))


def print_stats_unlabelled(y, guesses):
    """Statistics for unlabelled data"""
    log.info('guess percentage of anomalies: {percentage:.2f}'.format(
        percentage=(100 * np.count_nonzero(guesses == -1)) / len(guesses)))
