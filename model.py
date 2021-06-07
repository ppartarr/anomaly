#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

from sklearn.ensemble import IsolationForest, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.metrics import roc_auc_score, silhouette_score
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.feature_selection import SelectKBest
from sklearn.mixture import GaussianMixture
import numpy as np
import logging as log

from utils import print_stats


log.basicConfig(format='%(asctime)s.%(msecs)06d: %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S', level=log.INFO)


def train_gboost(x, y, x_train, x_test, y_train, y_test):
    """Train & test the Gradient Boosting Model"""
    log.info('Training the Gradient Boosting Model')
    gboost = GradientBoostingClassifier(
        n_estimators=80,
        verbose=1)

    classifier = gboost.fit(x_train, y_train)
    guesses = classifier.predict(x_test)

    print_stats(y, guesses, y_test)


def train_gmm(x, y, x_train, x_test, y_train, y_test):
    """Train & test the Gaussian Mixture Model"""
    log.info('Training the Gaussian Mixture Model')
    gmm = GaussianMixture(n_components=1,
        covariance_type='full',
        verbose=1,
        n_init=3
    )

    classifier = gmm.fit(x_train)
    guesses = classifier.predict(x_test)

    print_stats(y, guesses, y_test)


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


def find_best_features(x, x_train, y_train):
    select = SelectKBest(k=30)
    selected_features = select.fit(x_train, y_train)
    indices_selected = selected_features.get_support(indices=True)
    col_names_selected = [x.columns[i] for i in indices_selected]
    return col_names_selected


def iforest_tuning(x_train, y_train):
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


def gmm_tuning(x_train, y_train):
    """ Tune the model by testing various hyperparameters using the GridSearchCV"""

    gmm = GaussianMixture(verbose=1)

    param_grid = {'n_components': [1, 5, 10],
        'covariance_type': ['full', 'tied', 'diag', 'spherical'],
        'tol': [1**-3.5, 1**-3, 1**-2.5,],
        'max_iter': [80, 100, 120],
        'n_init': [1, 3, 5],
        'init_params': ['kmeans', 'random']}

    grid_search = GridSearchCV(gmm,
        param_grid,
        scoring="silhouette_score",
        refit=True,
        return_train_score=True,
        verbose=1)

    # TODO use labels to do supervised learning
    best_model = grid_search.fit(x_train, y_train)

    print('Best parameters', best_model.best_params_)