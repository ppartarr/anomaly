#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

from sklearn.neighbors import LocalOutlierFactor
from dask_ml.metrics import accuracy_score, log_loss
from dask_ml.model_selection import HyperbandSearchCV


from anomaly.models.stats import print_stats_labelled
from anomaly.config import n_jobs

import logging as log
import numpy as np
import joblib
import dask.dataframe as dd


class LOF:
    """Local Outlier Factor model"""

    def __init__(self, x, y, x_train, x_test, y_train, y_test):
        self.x = x.compute() if isinstance(x, dd.DataFrame) else x
        self.y = y.compute() if isinstance(y, dd.Series) else y
        self.x_train = x_train.compute() if isinstance(x_train, dd.DataFrame) else x_train
        self.x_test = x_test.compute() if isinstance(x_test, dd.DataFrame) else x_test
        self.y_train = y_train.compute() if isinstance(y_train, dd.Series) else y_train
        self.y_test = y_test.compute() if isinstance(y_test, dd.Series) else y_test

        self.lof = None
        self.params = None
        self.name = 'lof'

    def train(self):
        """Train the Local Outlier Factor model
        Note that the sci-kit learn API doesn't support .predict() when using LOF for outlier detection
        https://scikit-learn.org/stable/modules/outlier_detection.html#outlier-detection"""

        log.info('Training the Local Outlier Factor model')

        contamination = 1 - ((self.y.value_counts()[1]) / len(self.y))
        log.info('contamination rate: {contam:0.2f}%'.format(contam=100*contamination))

        if not self.params:
            # Best parameters {'leaf_size': 20, 'n_neighbors': 10}
            self.params = {'contamination': contamination,
                           'leaf_size': 20,
                           'n_neighbors': 10,
                           'n_jobs': n_jobs}

        self.lof = LocalOutlierFactor(**self.params)

        with joblib.parallel_backend('dask'):
            guesses = self.lof.fit_predict(self.x)

        # log.info('accuracy {acc}'.format(acc=accuracy_score(self.y_test, guesses)))
        # log.info('log loss {ll}'.format(ll=log_loss(self.y_test, guesses).mean()))

        print_stats_labelled(self.y, guesses, self.y, self.name, self.params)

    def predict(self, x):
        return self.lof.predict(x)

    def tune(self):
        """ Tune the model by testing various hyperparameters using the GridSearchCV"""

        lof = LocalOutlierFactor()

        param_grid = {'n_neighbors': [10, 20, 30],
                      'leaf_size': [20, 30, 40]
                      }

        grid_search = HyperbandSearchCV(lof,
                                        param_grid,
                                        max_iter=10,
                                        verbose=1)

        best_model = grid_search.fit(self.x_train, self.y_train)
        self.params = best_model.best_params_

        log.info('Best parameters {best}'.format(best=best_model.best_params_))
