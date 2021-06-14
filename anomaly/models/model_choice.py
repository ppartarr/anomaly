#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

from anomaly.models.isolation_forest import IForest
from anomaly.models.gradient_boost import GBoost
from anomaly.models.gaussian_mixture import GMix
from anomaly.models.local_outlier_factor import LOF
from anomaly.models.robust_covariance import RobustCovariance
from anomaly.models.svm import SVM
from anomaly.models.kitsune import Kitsune

model_choice = {
    # offline
    'IForest': IForest,
    'GBoost': GBoost,
    'LOF': LOF,
    'GMix': GMix,
    'RobustCovariance': RobustCovariance,
    'SVM': SVM,
    # online
    'Kitsune': Kitsune
}


def is_model_online(model):
    return model == 'Kitsune'
