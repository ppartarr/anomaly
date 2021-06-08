#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

from sklearn.ensemble import IsolationForest, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.metrics import roc_auc_score
from sklearn.feature_selection import SelectKBest
from sklearn.mixture import GaussianMixture
import numpy as np
import logging as log

from .stats import print_stats


log.basicConfig(format='%(asctime)s.%(msecs)06d: %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S', level=log.INFO)

def train_iforest(x, y, x_train, x_test, y_train, y_test):
    """Train & test the Isolation Forest model"""
    log.info('Training the Isolation Forest')
    contamination = 1 - ((y.value_counts()[1]) / len(y))
    log.info('contamination rate: {contam:0.2f}%'.format(contam=100*contamination))
    iforest = IsolationForest(n_estimators=80,
        max_features=30,
        contamination=contamination,
        n_jobs=1,
        verbose=1)

    classifier = iforest.fit(x_train)
    guesses = classifier.predict(x_test)

    print_stats(y, guesses, y_test)


def train_iforest_without_labels(x, x_train, x_test):
    """Train & test the Isolation Forest model without labels"""
    log.info('Training the Isolation Forest')
    iforest = IsolationForest(n_estimators=80,
        # max_features=30,
        n_jobs=1,
        verbose=1)

    classifier = iforest.fit(x_train)
    guesses = classifier.predict(x_test)
    log.info(np.unique(guesses, return_counts=True))
    # print_stats(guesses)


def tune_iforest(x_train, y_train):
    """ Tune the model by testing various hyperparameters using the GridSearchCV"""

    iforest = IsolationForest(verbose=1)

    param_grid = {'n_estimators': [40, 60, 80],
        'max_samples': ['auto'],
        'contamination': ['auto'],
        'max_features': [20, 30],
        'bootstrap': [False],
        'n_jobs': [-1]}

    grid_search = GridSearchCV(iforest,
        param_grid,
        scoring="roc_auc_score",
        refit=True,
        return_train_score=True,
        verbose=1)

    # TODO use labels to do supervised learning
    best_model = grid_search.fit(x_train, y_train)

    print('Best parameters', best_model.best_params_)