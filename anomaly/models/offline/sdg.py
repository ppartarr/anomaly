#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

from sklearn.linear_model import SGDClassifier
from dask_ml.metrics import accuracy_score, log_loss
from dask_ml.model_selection import HyperbandSearchCV
from dask_ml.preprocessing import StandardScaler

from anomaly.models.stats import print_stats_labelled
from sklearn.pipeline import make_pipeline

import logging as log
import numpy as np
import dask.dataframe as dd
import joblib


class SDG:
    """One Class Support Vector Machine"""

    def __init__(self, x, y, x_train, x_test, y_train, y_test):
        self.x = x.compute() if isinstance(x, dd.DataFrame) else x
        self.y = y.compute() if isinstance(y, dd.Series) else y
        self.x_train = x_train.compute() if isinstance(x_train, dd.DataFrame) else x_train
        self.x_test = x_test.compute() if isinstance(x_test, dd.DataFrame) else x_test
        self.y_train = y_train.compute() if isinstance(y_train, dd.Series) else y_train
        self.y_test = y_test.compute() if isinstance(y_test, dd.Series) else y_test

        self.sdg = None
        self.params = None

    def train(self):
        """Train the Support Vector Machine model"""
        log.info('Training SVM with Stochastic Gradient Descent learning')

        if not self.params:
            self.params = {'verbose': True}

        self.sdg = make_pipeline(
            StandardScaler(),
            SGDClassifier(**self.params)
        )

        with joblib.parallel_backend('dask'):
            classifier = self.sdg.fit(self.x_train, self.y_train)

        guesses = classifier.predict(self.x_test)

        # log.info('accuracy {acc}'.format(acc=accuracy_score(self.y_test, guesses)))
        # log.info('log loss {ll}'.format(ll=log_loss(self.y_test, guesses).mean()))

        print_stats_labelled(self.y, guesses, self.y_test)

    def predict(self, x):
        return self.sdg.predict(x)

    def tune(self):
        """ Tune the model by testing various hyperparameters using the GridSearchCV"""

        sdg = SGDClassifier(verbose=True)

        param_grid = {'kernel': ['linear', 'poly', 'rbf', 'sigmoid', 'precomputed'],
                      'degree': [2, 3, 4],
                      'gamma': ['scale', 'auto']
                      }

        grid_search = HyperbandSearchCV(sdg,
                                        param_grid,
                                        max_iter=10,
                                        verbose=1)

        best_model = grid_search.fit(self.x_train, self.y_train)
        self.params = best_model.best_params_

        log.info('Best parameters {best}'.format(best=best_model.best_params_))
