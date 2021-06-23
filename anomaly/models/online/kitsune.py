#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

from anomaly.extractors.raw_packets import RawPacketFeatureExtractor
from anomaly.extractors.audit.connections import ConnectionFeatureExtractor
from anomaly.models.online.kitnet.kitnet import KitNET
from anomaly.models.stats import plot, print_stats_online
from anomaly.utils import process_netcap_labels
import logging as log
import numpy as np
from scipy.stats import norm

from matplotlib import pyplot as plt
from matplotlib import cm


class Kitsune:
    """Ensemble of auto-encoders"""

    def __init__(self, path, reader, limit, feature_extractor, max_autoencoder_size=10, feature_mapping_training_samples=None, anomaly_detector_training_samples=10000, learning_rate=0.1, hidden_ratio=0.75, encoded=False, labelled=False):
        self.name = 'Kitsune'
        self.path = path
        self.encoded = encoded
        self.labelled = labelled

        self.feature_mapping_training_samples = feature_mapping_training_samples
        self.anomaly_detector_training_samples = anomaly_detector_training_samples

        self.feature_extractor = feature_extractor(path, reader, limit, encoded, labelled)

        # init Kitnet
        self.anomaly_detector = KitNET(self.feature_extractor.get_num_features(),
                                       max_autoencoder_size,
                                       feature_mapping_training_samples,
                                       anomaly_detector_training_samples,
                                       learning_rate,
                                       hidden_ratio)

    def proc_next_packet(self):
        values = self.feature_extractor.get_next_vector()
        if len(values) == 0:
            return -1  # Error or no packets left

        x, y = values

        # process KitNET
        result = self.anomaly_detector.process(x)
        return result, y  # will train during the grace periods, then execute on all the rest.

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
            root_mean_squared_errors[self.feature_mapping_training_samples+self.anomaly_detector_training_samples+1:])
        log_probs = norm.logsf(np.log(root_mean_squared_errors), np.mean(benign_sample), np.std(benign_sample))
        guesses = list(map(lambda x: 1 if x >= 0.5 else 0, root_mean_squared_errors))

        # convert string labels to int
        y_true = process_netcap_labels(y_true)
        print_stats_online(y_true, guesses)

        plot(self.name,
             './images/kitsune.png',
             root_mean_squared_errors,
             benign_sample,
             log_probs,
             self.anomaly_detector_training_samples,
             self.feature_mapping_training_samples
             )
