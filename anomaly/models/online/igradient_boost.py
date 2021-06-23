#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

import logging as log
import numpy as np

from anomaly.extractors.raw_packets import RawPacketFeatureExtractor
from anomaly.extractors.audit.connections import ConnectionFeatureExtractor
from anomaly.models.stats import plot

import anomaly.config as config
from scipy.stats import norm
from matplotlib import pyplot as plt
from matplotlib import cm

from xgboost import XGBClassifier


class IGBoost:
    """Dask Incremental Gradient Boosting"""

    def __init__(self, path, reader, limit, feature_extractor, anomaly_detector_training_samples=10000):
        self.name = 'Incremental GBoost'
        self.path = path
        self.current_packet_index = 0
        self.anomaly_detector_training_samples = anomaly_detector_training_samples

        self.feature_extractor = feature_extractor(path, reader, limit)

        self.ixgboost = XGBClassifier(
            n_estimators=80,
            max_depth=15,
            learning_rate=0.15,
            verbosity=3,
            n_jobs=config.n_jobs
        )

    def proc_next_packet(self):
        x = self.feature_extractor.get_next_vector()
        if len(x) == 0:
            return -1  # Error or no packets left

        # log.info(x)
        # log.info(type)

        if self.current_packet_index < self.anomaly_detector_training_samples:
            # TODO: add labels as y
            self.ixgboost = self.ixgboost.fit(x, verbose=True, xgb_model=self.ixgboost)

        result = self.ixgboost.predict(x)
        # TODO write result to socket?

        return result

    def run(self):
        root_mean_squared_errors = []
        i = 0
        while True:
            i += 1
            if i % 1000 == 0:
                log.info(i)
            rmse = self.proc_next_packet()
            if rmse == -1:
                break
            root_mean_squared_errors.append(rmse)

        benign_sample = np.log(
            root_mean_squared_errors[self.anomaly_detector_training_samples+1:100000])
        log_probs = norm.logsf(np.log(root_mean_squared_errors), np.mean(benign_sample), np.std(benign_sample))

        plot(self.name,
             './images/igboost.png',
             root_mean_squared_errors,
             benign_sample,
             log_probs,
             self.anomaly_detector_training_samples
             )
