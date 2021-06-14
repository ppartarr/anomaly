#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

from skgarden import MondrianForestClassifier

import numpy as np
import logging as log

from anomaly.models.stats import print_stats


def train_mondrian(x, y, x_train, x_test, y_train, y_test):
    """Train & test the Mondrian Forest model"""
    log.info('Training the Mondrian Forest')
    mforest = MondrianForestClassifier(n_estimators=80,
                                       n_jobs=1,
                                       verbose=1)

    classifier = mforest.fit(x_train, y_train)
    # guesses = classifier.predict(x_test)
    # log.info(np.unique(guesses, return_counts=True))
    # print_stats(y, guesses, y_test)


def train_mondrian_without_labels(x, x_train, x_test):
    """Train & test the Mondrian Forest model without labelsy"""
    log.info('Training the Mondrian Forest')
    mforest = MondrianForestClassifier(n_estimators=80,
                                       n_jobs=1,
                                       verbose=1)

    # classifier = mforest.partial_fit(x_train)
    # guesses = classifier.predict(x_test)
    # log.info(np.unique(guesses, return_counts=True))
