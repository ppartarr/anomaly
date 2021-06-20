#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

from anomaly.models.offline.gradient_boost import GBoost
from anomaly.models.offline.isolation_forest import IForest
from anomaly.models.offline.gaussian_mixture import GMix
from anomaly.models.offline.local_outlier_factor import LOF
from anomaly.models.offline.svm import SVM

from anomaly.models.online.kitsune import Kitsune
from anomaly.models.online.half_space_tree import HSTree
from anomaly.models.online.igradient_boost import IGBoost

model_choice = {
    # offline
    'iforest': IForest,
    'gboost': GBoost,
    # 'lof': LOF,
    'gmix': GMix,
    # 'svm': SVM,
    'offline': [IForest, GBoost, GMix],
    # online
    'kitsune': Kitsune,
    'hstree': HSTree,    # incremental iforest
    'igboost': IGBoost,  # incremental gradient boost
    'online': [Kitsune, HSTree, IGBoost]
}


def is_model_online(model):
    return model_choice[model] in model_choice['online']
