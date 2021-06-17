#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

from sklearn.neighbors import LocalOutlierFactor
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV

from anomaly.models.stats import print_stats_labelled
from anomaly.config import n_jobs

import logging as log
import numpy as np

log = log.getLogger(__name__)


class LOF:
    """Local Outlier Factor model"""

    def __init__(self, x, y, x_train, x_test, y_train, y_test):
        self.x = x
        self.y = y
        self.x_train = x_train
        self.x_test = x_test
        self.y_train = y_train
        self.y_test = y_test

        self.lof = None
        self.params = None

    def train(self):
        """Train the Local Outlier Factor model
        Note that the sci-kit learn API doesn't support .predict() when using LOF for outlier detection
        https://scikit-learn.org/stable/modules/outlier_detection.html#outlier-detection"""

        log.info('Training the Local Outlier Factor model')
        # Training with labels
        if not self.y.empty:

            contamination = 1 - ((self.y.value_counts()[1]) / len(self.y))
            log.info('contamination rate: {contam:0.2f}%'.format(contam=100*contamination))

            if not self.params:
                # Best parameters {'leaf_size': 20, 'n_neighbors': 10}
                self.params = {'contamination': contamination,
                               'leaf_size': 20,
                               'n_neighbors': 10,
                               'n_jobs': n_jobs}

            self.lof = LocalOutlierFactor(**self.params)

            guesses = self.lof.fit_predict(self.x)
            # n_errors = (guesses != self.y_train).sum()
            # x_scores = self.lof.negative_outlier_factor_

            # log.info('n errors {n_errors}'.format(n_errors=n_errors))
            # log.info('x scores {x_scores}'.format(X_scores=x_scores))

            print_stats_labelled(self.y, guesses, self.y)
        # Training without labels
        else:
            self.lof = LocalOutlierFactor(
                n_jobs=n_jobs
            )

            classifier = self.lof.fit(self.x_train)
            guesses = classifier.predict(self.x_test)

            guesses = self.lof.fit_predict(self.x_train)
            n_errors = (guesses != self.y_train).sum()
            # x_scores = self.lof.negative_outlier_factor_

            log.info('n errors {n_errors}'.format(n_errors=n_errors))
            # log.info('x scores {x_scores}'.format(X_scores=x_scores))

    def predict(self, x):
        return self.lof.predict(x)

    def tune(self):
        """ Tune the model by testing various hyperparameters using the GridSearchCV"""

        lof = LocalOutlierFactor()

        param_grid = {'n_neighbors': [10, 20, 30],
                      'leaf_size': [20, 30, 40]
                      }

        grid_search = GridSearchCV(lof,
                                   param_grid,
                                   scoring=roc_auc_score,
                                   refit=True,
                                   return_train_score=True,
                                   verbose=1)

        best_model = grid_search.fit(self.x_train, self.y_train)
        self.params = best_model.best_params_

        print('Best parameters', best_model.best_params_)
