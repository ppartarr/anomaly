#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

from sklearn.feature_selection import SelectKBest
from sklearn.mixture import GaussianMixture
from sklearn.model_selection import GridSearchCV
from sklearn.metrics import silhouette_score

import logging as log
import dask.dataframe as dd

from anomaly.models.stats import print_stats_labelled


class GMix:
    """Gaussian Mixture model"""

    def __init__(self, x, y, x_train, x_test, y_train, y_test):
        self.x = x.compute() if isinstance(x, dd.DataFrame) else x
        self.y = y.compute() if isinstance(y, dd.Series) else y
        self.x_train = x_train.compute() if isinstance(x_train, dd.DataFrame) else x_train
        self.x_test = x_test.compute() if isinstance(x_test, dd.DataFrame) else x_test
        self.y_train = y_train.compute() if isinstance(y_train, dd.Series) else y_train
        self.y_test = y_test.compute() if isinstance(y_test, dd.Series) else y_test

        self.gmm = None
        self.params = None
        self.name = 'gmix'

    def train(self):
        """Train & test the Gaussian Mixture Model"""
        log.info('Training the Gaussian Mixture Model')

        if not self.params:
            self.params = {'n_components': 2,
                           'covariance_type': 'full',
                           'verbose': 1,
                           'n_init': 10,
                           'reg_covar': 1e-5,
                           'tol': 1.0}

        self.gmm = GaussianMixture(**self.params)

        classifier = self.gmm.fit(self.x_train)
        guesses = classifier.predict(self.x_test)

        print_stats_labelled(self.y, guesses, self.y_test, self.name, self.params)

    def predict(self, x):
        return self.gmm.predict(x)

    def tune(self):
        """ Tune the model by testing various hyperparameters using the GridSearchCV"""

        self.gmm = GaussianMixture(verbose=1)

        param_grid = [{'n_components': [1, 5, 10],
                      'covariance_type': ['full'],
                       'tol': [1**-3.5, 1**-3, 1**-2.5],
                       'max_iter': [80, 100, 120],
                       'n_init': [1, 3, 5],
                       'reg_covar': [1e-5, 1e-6, 1e-7]
                       }
                      ]

        grid_search = GridSearchCV(self.gmm,
                                   param_grid,
                                   scoring=silhouette_score,
                                   refit=True,
                                   return_train_score=True,
                                   verbose=1)

        best_model = grid_search.fit(self.x_train, self.y_train)

        self.params = best_model.best_params_

        log.info('Best parameters {best}'.format(best=best_model.best_params_))
