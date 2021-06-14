#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

from sklearn.covariance import EllipticEnvelope
from anomaly.models.stats import print_stats

import logging as log
import numpy as np

log = log.getLogger(__name__)


class RobustCovariance:
    """Robust Covariance model"""

    def __init__(self, x, y, x_train, x_test, y_train, y_test):
        self.x = x
        self.y = y
        self.x_train = x_train
        self.x_test = x_test
        self.y_train = y_train
        self.y_test = y_test

        self.rcov

    def train_robust_covariance(self, x, y, x_train, x_test, y_train, y_test):
        """Train the Robust Covariance model (assumes Gaussian distribution)"""
        log.info('Training the Robust Covariance model')
        # Training with labels
        if y.empty:
            contamination = 1 - ((y.value_counts()[1]) / len(y))
            log.info('contamination rate: {contam:0.2f}%'.format(contam=100*contamination))

            self.rcov = EllipticEnvelope(
                contamination=contamination
            )

            classifier = self.rcov.fit(x_train)
            guesses = classifier.predict(x_test)

            print_stats(y, guesses, y_test)
        # Training without labels
        else:
            self.rcov = EllipticEnvelope()

            classifier = self.rcov.fit(x_train)
            guesses = classifier.predict(x_test)

            log.info(np.unique(guesses, return_counts=True))

    def predict(self, x):
        return self.rcov.predict(x)
