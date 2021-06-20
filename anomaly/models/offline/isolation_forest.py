#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

from sklearn.ensemble import IsolationForest, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.metrics import roc_auc_score
from sklearn.feature_selection import SelectKBest
from sklearn.mixture import GaussianMixture
import numpy as np
import logging as log

from anomaly.models.stats import print_stats_labelled, print_stats_unlabelled
from anomaly.config import n_jobs

log = log.getLogger(__name__)


class IForest:
    """Isolation Forest model"""

    def __init__(self, x, y, x_train, x_test, y_train, y_test):
        self.x = x
        self.y = y
        self.x_train = x_train
        self.x_test = x_test
        self.y_train = y_train
        self.y_test = y_test

        self.iforest = None
        self.params = None

    def train(self):
        """Train & test the Isolation Forest model with or without labels"""
        log.info('Training the Isolation Forest')

        # train with labels
        if not self.y.empty:

            contamination = 1 - ((self.y.value_counts()[1]) / len(self.y))
            log.info('contamination rate: {contam:0.2f}%'.format(contam=100*contamination))

            # set params manually if model has not been tuned yet
            if not self.params:
                self.params = {'n_estimators': 80,
                               'max_features': 30,
                               'contamination': contamination,
                               'n_jobs': n_jobs,
                               'verbose': 1}

            self.iforest = IsolationForest(**self.params,)

            classifier = self.iforest.fit(self.x_train)
            guesses = classifier.predict(self.x_test)

            print_stats_labelled(self.y, guesses, self.y_test)
            # train without labels
        else:
            self.iforest = IsolationForest(n_estimators=80,
                                           # max_features=30,
                                           n_jobs=n_jobs,
                                           verbose=1)

            classifier = self.iforest.fit(self.x_train)
            guesses = classifier.predict(self.x_test)

            log.info(np.unique(guesses, return_counts=True))
            print_stats_unlabelled(self.y, guesses)

    def predict(self, x):
        return self.iforest.predict(x)

    def tune(self):
        """ Tune the model by testing various hyperparameters using the GridSearchCV"""

        iforest = IsolationForest(verbose=1, n_jobs=n_jobs)

        param_grid = {'n_estimators': [40, 60, 80],
                      'max_features': [20, 30]
                      }

        grid_search = GridSearchCV(iforest,
                                   param_grid,
                                   scoring=roc_auc_score,
                                   refit=True,
                                   return_train_score=True,
                                   verbose=1)

        best_model = grid_search.fit(self.x_train, self.y_train)
        self.params = best_model.best_params_
        log.info(best_model.best_params_)

        log.info('Best parameters', best_model.best_params_)
