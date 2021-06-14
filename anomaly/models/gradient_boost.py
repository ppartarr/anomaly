#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split, GridSearchCV
import logging as log

from anomaly.models.stats import print_stats


class GBoost:
    """Gradient Boosting Model"""

    def __init__(self, x, y, x_train, x_test, y_train, y_test):
        self.x = x
        self.y = y
        self.x_train = x_train
        self.x_test = x_test
        self.y_train = y_train
        self.y_test = y_test

        self.gboost

    def train(self, x, y, x_train, x_test, y_train, y_test):
        """Train & test the Gradient Boosting Model"""
        log.info('Training the Gradient Boosting Model')
        self.gboost = GradientBoostingClassifier(
            n_estimators=80,
            verbose=1)

        classifier = self.gboost.fit(x_train, y_train)
        guesses = classifier.predict(x_test)

        print_stats(y, guesses, y_test)

    def predict(self, x):
        return self.gboost.predict(x)

    def tune(self):
        """ Tune the model by testing various hyperparameters using the GridSearchCV"""

        iforest = GradientBoostingClassifier(verbose=1)

        param_grid = {
            'n_estimators': [80, 100, 120],
            'loss': ['deviance', 'exponential'],
            'learning_rate': [0.15, 0.1, 0.05],
            'subsample': [1.0, ],
            'criterion': ['friedman_mse', 'mse', 'mae'],
            'bootstrap': [False],
            'n_jobs': [-1]}

        grid_search = GridSearchCV(iforest,
                                   param_grid,
                                   scoring="roc_auc_score",
                                   refit=True,
                                   return_train_score=True,
                                   verbose=1)

        best_model = grid_search.fit(self.x_train, self.y_train)

        print('Best parameters', best_model.best_params_)
