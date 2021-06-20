#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

from anomaly.extractors.raw_packets import RawPacketFeatureExtractor
from anomaly.extractors.audit.connections import ConnectionFeatureExtractor
from anomaly.models.online.kitnet.kitnet import KitNET
import logging as log
import numpy as np
from scipy.stats import norm

from matplotlib import pyplot as plt
from matplotlib import cm


class Kitsune:
    """Ensemble of auto-encoders"""

    def __init__(self, path, reader, limit, feature_extractor, max_autoencoder_size=10, feature_mapping_training_samples=None, anomaly_detector_training_samples=10000, learning_rate=0.1, hidden_ratio=0.75, encoded=False):

        self.path = path
        self.encoded = encoded

        self.feature_mapping_training_samples = feature_mapping_training_samples
        self.anomaly_detector_training_samples = anomaly_detector_training_samples

        self.feature_extractor = feature_extractor(path, reader, limit, encoded)

        # init Kitnet
        self.anomaly_detector = KitNET(self.feature_extractor.get_num_features(),
                                       max_autoencoder_size,
                                       feature_mapping_training_samples,
                                       anomaly_detector_training_samples,
                                       learning_rate,
                                       hidden_ratio)

    def proc_next_packet(self):
        x = self.feature_extractor.get_next_vector()
        if len(x) == 0:
            return -1  # Error or no packets left

        # process KitNET
        result = self.anomaly_detector.process(x)
        return result  # will train during the grace periods, then execute on all the rest.

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
            root_mean_squared_errors[self.feature_mapping_training_samples+self.anomaly_detector_training_samples+1:10000])
        log_probs = norm.logsf(np.log(root_mean_squared_errors), np.mean(benign_sample), np.std(benign_sample))

        # plot the RMSE anomaly scores
        log.info("Plotting results")
        plt.figure(figsize=(10, 5))
        fig = plt.scatter(
            range(self.feature_mapping_training_samples +
                  self.anomaly_detector_training_samples+1, len(root_mean_squared_errors)),
            root_mean_squared_errors[self.feature_mapping_training_samples+self.anomaly_detector_training_samples+1:],
            s=0.1,
            c=log_probs[self.feature_mapping_training_samples+self.anomaly_detector_training_samples+1:],
            cmap='RdYlGn')
        plt.yscale("log")
        plt.title("Anomaly Scores from Kitsune's Execution Phase")
        plt.ylabel("RMSE (log scaled)")
        plt.xlabel("Time elapsed [min]")
        figbar = plt.colorbar()
        figbar.ax.set_ylabel('Log Probability\n ', rotation=270)
        plt.show()
