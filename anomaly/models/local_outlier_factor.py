#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

from sklearn.neighbors import LocalOutlierFactor
from anomaly.models.stats import print_stats

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

        self.lof

    def train(self, x, y, x_train, x_test, y_train, y_test):
        """Train the Local Outlier Factor model
        Note that the sci-kit learn API doesn't support .predict when using LOF for outlier detection
        https://scikit-learn.org/stable/modules/outlier_detection.html#outlier-detection"""

        log.info('Training the Local Outlier Factor model')
        # Training with labels
        if not y.empty:
            contamination = 1 - ((y.value_counts()[1]) / len(y))
            log.info('contamination rate: {contam:0.2f}%'.format(contam=100*contamination))
            self.lof = LocalOutlierFactor(
                contamination=contamination,
                n_jobs=4
            )

            guesses = self.lof.fit_predict(x_train)
            n_errors = (guesses != y_train).sum()
            x_scores = self.lof.negative_outlier_factor_

            print('n errors {n_errors}'.format(n_errors=n_errors))
            print('x scores {x_scores}'.format(X_scores=x_scores))
        # Training without labels
        else:
            self.lof = LocalOutlierFactor(
                n_jobs=-1
            )

            classifier = self.lof.fit(x_train)
            guesses = classifier.predict(x_test)

            guesses = self.lof.fit_predict(x_train)
            n_errors = (guesses != y_train).sum()
            x_scores = self.lof.negative_outlier_factor_

            print('n errors {n_errors}'.format(n_errors=n_errors))
            print('x scores {x_scores}'.format(X_scores=x_scores))

    def predict(self, x):
        return self.lof.predict(x)
