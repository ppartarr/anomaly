#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

from anomaly.models.isolation_forest import IForest
from anomaly.models.gradient_boost import GBoost
from anomaly.models.gaussian_mixture import GMix
from anomaly.models.local_outlier_factor import LOF
from anomaly.models.svm import SVM
from anomaly.models.kitsune import Kitsune
from anomaly.models.half_space_tree import HSTree

model_choice = {
    # offline
    'IForest': IForest,
    'GBoost': GBoost,
    'LOF': LOF,
    'GMix': GMix,
    'SVM': SVM,
    'Offline': [IForest, GBoost, LOF, GMix, SVM],
    # online
    'Kitsune': Kitsune,
    'HSTree': HSTree
}


def is_model_online(model):
    return model == 'Kitsune' or model == 'HSTree'
