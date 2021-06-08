#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split
import logging as log

from anomaly.models.utils import print_stats


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