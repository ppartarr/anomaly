#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

import logging as log
import numpy as np

from anomaly.extractors.raw_packets import RawPacketFeatureExtractor
from anomaly.extractors.audit.connections import ConnectionFeatureExtractor
from anomaly.models.stats import plot
from anomaly.models.stats import plot, print_stats_online
from anomaly.utils import process_netcap_label
from anomaly.models.stats import plot

import anomaly.config as config
from scipy.stats import norm
from matplotlib import pyplot as plt
from matplotlib import cm

from xgboost import XGBClassifier


class IGBoost:
    """Dask Incremental Gradient Boosting"""

    def __init__(self, path, reader, limit, feature_extractor, anomaly_detector_training_samples=10000, encoded=False, labelled=False):
        self.name = 'Incremental GBoost'
        self.path = path
        self.current_packet_index = 0
        self.labelled = labelled
        self.anomaly_detector_training_samples = anomaly_detector_training_samples

        self.feature_extractor = feature_extractor(path, reader, limit, encoded, labelled)

        self.ixgboost = XGBClassifier(
            n_estimators=80,
            max_depth=15,
            learning_rate=0.15,
            verbosity=3,
            n_jobs=config.n_jobs
        )

    def proc_next_packet(self):
        values = self.feature_extractor.get_next_vector()
        if len(values) == 0:
            return -1  # Error or no packets left

        x, y = values

        if self.current_packet_index < self.anomaly_detector_training_samples and self.labelled:
            y = process_netcap_label(y)
            self.ixgboost = self.ixgboost.fit(x, [y], verbose=True, xgb_model=self.ixgboost)

        x = self.ixgboost.predict(x)

        # TODO write result to socket?
        return x, y

    def run(self):
        root_mean_squared_errors = []
        y_true = []
        i = 0
        while True:
            i += 1
            if i % 1000 == 0:
                log.info(i)
            values = self.proc_next_packet()
            if values == -1:
                break
            rmse, y = values
            root_mean_squared_errors.append(rmse)

            if self.labelled:
                y_true.append(y)

        benign_sample = np.log(
            root_mean_squared_errors[self.anomaly_detector_training_samples+1:100000])
        log_probs = norm.logsf(np.log(root_mean_squared_errors), np.mean(benign_sample), np.std(benign_sample))

        if self.labelled:
            guesses = list(map(lambda x: 1 if x >= 0.5 else 0, root_mean_squared_errors))
            print_stats_online(y_true, guesses)

        file_name = './images/{model}-{len}.png'.format(model=self.name, len=len(root_mean_squared_errors))

        plot(self.name,
             file_name,
             root_mean_squared_errors,
             benign_sample,
             log_probs,
             self.anomaly_detector_training_samples
             )
