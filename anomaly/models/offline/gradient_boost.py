#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import roc_auc_score
import logging as log

from anomaly.models.stats import print_stats_labelled


class GBoost:
    """Gradient Boosting Model"""

    def __init__(self, x, y, x_train, x_test, y_train, y_test):
        self.x = x
        self.y = y
        self.x_train = x_train
        self.x_test = x_test
        self.y_train = y_train
        self.y_test = y_test

        self.gboost = None
        self.params = None

    def train(self):
        """Train & test the Gradient Boosting Model"""
        log.info('Training the Gradient Boosting Model')

        if not self.params:
            self.params = {'learning_rate': 0.15,
                           'n_estimators': 80,
                           'verbose': 1}
        self.gboost = GradientBoostingClassifier(**self.params)

        classifier = self.gboost.fit(self.x_train, self.y_train)
        guesses = classifier.predict(self.x_test)

        print_stats_labelled(self.y, guesses, self.y_test)

    def predict(self, x):
        return self.gboost.predict(x)

    def tune(self):
        """ Tune the model by testing various hyperparameters using the GridSearchCV"""

        gboost = GradientBoostingClassifier(verbose=1)

        # Best parameters {'learning_rate': 0.15, 'loss': 'deviance', 'n_estimators': 80, 'subsample': 0.8}
        param_grid = [{
            'n_estimators': [80, 100, 120],
            'loss': ['deviance'],
            'learning_rate': [0.15, 0.1, 0.05],
            'subsample': [0.8, 1.0, 1.2]
        },
            {
            'n_estimators': [80, 100, 120],
            'loss': ['exponential'],
            'learning_rate': [0.15, 0.1, 0.05],
            'subsample': [0.8, 1.0, 1.2]
        }]

        grid_search = GridSearchCV(gboost,
                                   param_grid,
                                   scoring=roc_auc_score,
                                   refit=True,
                                   return_train_score=True,
                                   verbose=1)

        best_model = grid_search.fit(self.x_train, self.y_train)

        self.params = best_model.best_params_

        log.info('Best parameters', best_model.best_params_)
