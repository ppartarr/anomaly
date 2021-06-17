#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

import logging as log
import numpy as np

from anomaly.extractors.raw_packets import RawPacketFeatureExtractor
from anomaly.extractors.connections import ConnectionFeatureExtractor
from scipy.stats import norm
from matplotlib import pyplot as plt
from matplotlib import cm

from river import metrics, compose, preprocessing
from river.anomaly import HalfSpaceTrees


class HSTree:
    """Half Space Tree (online Isolation Forest variant)
    https://riverml.xyz/latest/api/anomaly/HalfSpaceTrees/"""

    def __init__(self, path, reader, limit, feature_extractor, anomaly_detector_training_samples=10000):
        self.path = path
        self.current_packet_index = 0
        self.anomaly_detector_training_samples = anomaly_detector_training_samples

        self.feature_extractor = feature_extractor(path, reader, limit)

        self.rocauc = metrics.ROCAUC()

        self.hstree = compose.Pipeline(
            preprocessing.MinMaxScaler(),
            HalfSpaceTrees(
                n_trees=30,
                height=16,
                window_size=255)
        )

    def proc_next_packet(self):
        x = self.feature_extractor.get_next_vector()
        if len(x) == 0:
            return -1  # Error or no packets left

        # log.info(x)
        # log.info(type)

        if self.current_packet_index < self.anomaly_detector_training_samples:
            # convert np array to dict for river api...
            self.hstree = self.hstree.learn_one(dict(enumerate(x.flatten(), 1)))

        result = self.hstree.score_one(dict(enumerate(x.flatten(), 1)))
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

        log.info(self.rocauc)

        benign_sample = np.log(
            root_mean_squared_errors[self.anomaly_detector_training_samples+1:100000])
        log_probs = norm.logsf(np.log(root_mean_squared_errors), np.mean(benign_sample), np.std(benign_sample))

        # plot the RMSE anomaly scores
        log.info("Plotting results")
        plt.figure(figsize=(10, 5))
        fig = plt.scatter(
            range(self.anomaly_detector_training_samples+1, len(root_mean_squared_errors)),
            root_mean_squared_errors[self.anomaly_detector_training_samples+1:],
            s=0.1,
            c=log_probs[self.anomaly_detector_training_samples+1:],
            cmap='RdYlGn')
        plt.yscale("log")
        plt.title("Anomaly Scores from HSTree's Execution Phase")
        plt.ylabel("RMSE (log scaled)")
        plt.xlabel("Time elapsed [min]")
        figbar = plt.colorbar()
        figbar.ax.set_ylabel('Log Probability\n ', rotation=270)
        plt.show()
