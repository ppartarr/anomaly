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
    'iforest': IForest,
    'gboost': GBoost,
    'lof': LOF,
    'gmix': GMix,
    'svm': SVM,
    'offline': [IForest, GBoost, LOF, GMix, SVM],
    # online
    'kistune': Kitsune,
    'hstree': HSTree
}


def is_model_online(model):
    return model == 'kitsune' or model == 'hstree'
