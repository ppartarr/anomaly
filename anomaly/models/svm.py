#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

from sklearn.svm import OneClassSVM
from anomaly.models.stats import print_stats

import logging as log
import numpy as np

log = log.getLogger(__name__)


class SVM:
    """One Class Support Vector Machine"""

    def __init__(self, x, y, x_train, x_test, y_train, y_test):
        self.x = x
        self.y = y
        self.x_train = x_train
        self.x_test = x_test
        self.y_train = y_train
        self.y_test = y_test

        self.svm

    def train_lof(self, x, y, x_train, x_test, y_train, y_test):
        """Train the Support Vector Machine model"""
        log.info('Training the Support Vector Machine model')
        # Training with labels
        if y.empty():
            self.svm = OneClassSVM(
                verbose=True,
                cache_size=200  # in MBytes
            )

            classifier = self.svm.fit(x_train)
            guesses = classifier.predict(x_test)

            print_stats(y, guesses, y_test)
        # Training without labels
        else:
            self.svm = OneClassSVM(
                verbose=True,
                cache_size=200  # in MBytes
            )

            classifier = self.svm.fit(x_train)
            guesses = classifier.predict(x_test)

            log.info(np.unique(guesses, return_counts=True))

    def predict(self, x):
        return self.svm.predict(x)
