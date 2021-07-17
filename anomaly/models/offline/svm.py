#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

from sklearn.svm import OneClassSVM
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.metrics import roc_auc_score

from anomaly.models.stats import print_stats_labelled

import logging as log
import numpy as np
import dask.dataframe as dd

log = log.getLogger(__name__)


class SVM:
    """One Class Support Vector Machine"""

    def __init__(self, x, y, x_train, x_test, y_train, y_test):
        self.x = x.compute() if isinstance(x, dd.DataFrame) else x
        self.y = y.compute() if isinstance(y, dd.Series) else y
        self.x_train = x_train.compute() if isinstance(x_train, dd.DataFrame) else x_train
        self.x_test = x_test.compute() if isinstance(x_test, dd.DataFrame) else x_test
        self.y_train = y_train.compute() if isinstance(y_train, dd.Series) else y_train
        self.y_test = y_test.compute() if isinstance(y_test, dd.Series) else y_test

        self.svm = None
        self.params = None
        self.name = 'svm'

    def train(self):
        """Train the Support Vector Machine model"""
        log.info('Training the Support Vector Machine model')

        if not self.params:
            self.params = {'verbose': True}

        self.svm = OneClassSVM(**self.params, cache_size=4000)

        classifier = self.svm.fit(self.x_train)
        guesses = classifier.predict(self.x_test)

        print_stats_labelled(self.y, guesses, self.y_test, self.name, self.params)

    def predict(self, x):
        return self.svm.predict(x)

    def tune(self):
        """ Tune the model by testing various hyperparameters using the GridSearchCV"""

        svm = OneClassSVM(verbose=True)

        param_grid = {'kernel': ['linear', 'poly', 'rbf', 'sigmoid', 'precomputed'],
                      'degree': [2, 3, 4],
                      'gamma': ['scale', 'auto']
                      }

        grid_search = GridSearchCV(svm,
                                   param_grid,
                                   scoring=roc_auc_score,
                                   refit=True,
                                   return_train_score=True,
                                   verbose=1)

        best_model = grid_search.fit(self.x_train, self.y_train)
        self.params = best_model.best_params_

        log.info('Best parameters {best}'.format(best=best_model.best_params_))
