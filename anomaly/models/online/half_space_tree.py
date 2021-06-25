#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

import logging as log
import numpy as np

from anomaly.extractors.raw_packets import RawPacketFeatureExtractor
from anomaly.extractors.audit.connections import ConnectionFeatureExtractor
from anomaly.models.stats import plot, print_stats_online
from anomaly.utils import process_netcap_label
from anomaly.models.stats import plot

from scipy.stats import norm
from matplotlib import pyplot as plt
from matplotlib import cm

from river import metrics, compose, preprocessing
from river.anomaly import HalfSpaceTrees


class HSTree:
    """Half Space Tree (online Isolation Forest variant)
    https://riverml.xyz/latest/api/anomaly/HalfSpaceTrees/"""

    def __init__(self, path, reader, limit, feature_extractor, anomaly_detector_training_samples=10000, encoded=False, labelled=False):
        self.name = 'Half Space Tree'
        self.path = path
        self.current_packet_index = 0
        self.labelled = labelled
        self.anomaly_detector_training_samples = anomaly_detector_training_samples

        self.feature_extractor = feature_extractor(path, reader, limit, encoded, labelled)

        self.rocauc = metrics.ROCAUC()

        self.hstree = compose.Pipeline(
            preprocessing.MinMaxScaler(),
            HalfSpaceTrees(
                n_trees=30,
                height=16,
                window_size=255)
        )

    def proc_next_packet(self):
        values = self.feature_extractor.get_next_vector()
        if len(values) == 0:
            return -1  # Error or no packets left

        x, y = values

        if self.current_packet_index < self.anomaly_detector_training_samples and self.labelled:
            # convert np array to dict for river api...
            y = process_netcap_label(y)
            self.hstree = self.hstree.learn_one(x=dict(enumerate(x.flatten(), 1)), y=y)

        x = self.hstree.score_one(dict(enumerate(x.flatten(), 1)))

        # TODO write result to socket
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
