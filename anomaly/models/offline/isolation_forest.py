#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

from sklearn.ensemble import IsolationForest
from dask_ml.model_selection import HyperbandSearchCV
from dask_ml.metrics import accuracy_score, log_loss
import dask.dataframe as dd

import numpy as np
import logging as log
import joblib

from anomaly.models.stats import print_stats_labelled
from anomaly.config import n_jobs


class IForest:
    """Isolation Forest model"""

    def __init__(self, x, y, x_train, x_test, y_train, y_test):
        self.x = x.compute() if isinstance(x, dd.DataFrame) else x
        self.x_train = x_train.compute() if isinstance(x_train, dd.DataFrame) else x_train
        self.x_test = x_test.compute() if isinstance(x_test, dd.DataFrame) else x_test

        if len(y) != 0:
            self.y = y.compute() if isinstance(y, dd.Series) else y
            self.y_train = y_train.compute() if isinstance(y_train, dd.Series) else y_train
            self.y_test = y_test.compute() if isinstance(y_test, dd.Series) else y_test

        self.iforest = None
        self.params = None

    def train(self):
        """Train & test the Isolation Forest model with or without labels"""
        log.info('Training the Isolation Forest')

        contamination = 1 - ((self.y.value_counts()[1]) / len(self.y))
        log.info('contamination rate: {contam:0.2f}%'.format(contam=100*contamination))

        # set params manually if model has not been tuned yet
        if not self.params:
            self.params = {'n_estimators': 80,
                           'max_features': 30,
                           'contamination': contamination,
                           'n_jobs': n_jobs,
                           'verbose': 1,
                           'random_state': 42}

        self.iforest = IsolationForest(**self.params)

        # with joblib.parallel_backend('dask'):
        classifier = self.iforest.fit(self.x_train)

        guesses = classifier.predict(self.x_test)

        # log.info('accuracy {acc}'.format(acc=accuracy_score(self.y_test, guesses)))
        # log.info('log loss {ll}'.format(ll=log_loss(self.y_test, guesses).mean()))

        print_stats_labelled(self.y, guesses, self.y_test)

    def predict(self, x):
        return self.iforest.predict(x)

    def tune(self):
        """ Tune the model by testing various hyperparameters using the GridSearchCV"""

        iforest = IsolationForest(verbose=1, n_jobs=n_jobs)

        param_grid = {'n_estimators': [40, 60, 80],
                      'max_features': [20, 30]
                      }

        grid_search = HyperbandSearchCV(iforest,
                                        param_grid,
                                        max_iter=10,
                                        verbose=1)

        best_model = grid_search.fit(self.x_train, self.y_train)
        self.params = best_model.best_params_
        log.info(best_model.best_params_)

        log.info('Best parameters {best}'.format(best=best_model.best_params_))
