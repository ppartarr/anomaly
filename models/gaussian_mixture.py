#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

from sklearn.feature_selection import SelectKBest
from sklearn.mixture import GaussianMixture
from sklearn.model_selection import GridSearchCV

import logging as log

from .stats import print_stats

log.basicConfig(format='%(asctime)s.%(msecs)06d: %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S', level=log.INFO)


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


def tune_gmm(x_train, y_train):
    """ Tune the model by testing various hyperparameters using the GridSearchCV"""

    gmm = GaussianMixture(verbose=1)

    param_grid = {'n_components': [1, 5, 10],
                  'covariance_type': ['full', 'tied', 'diag', 'spherical'],
                  'tol': [1**-3.5, 1**-3, 1**-2.5, ],
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
