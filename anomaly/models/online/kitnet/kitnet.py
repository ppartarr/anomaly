#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

import numpy as np
from .auto_encoder import AutoEncoder, AutoEncoderParams
from .correlation_cluster import CorrelationCluster
import logging as log


class KitNET:
    """This class represents a KitNET machine learner.
    KitNET is a lightweight online anomaly detection algorithm based on an ensemble of autoencoders.

    n: the number of features in your input dataset (i.e., x \in R^n)
    m: the maximum size of any autoencoder in the ensemble layer
    anomaly_detector_training_samples: the number of instances the network will learn from before producing anomaly scores
    feature_mapping_training_samples: the number of instances which will be taken to learn the feature mapping. If 'None', then feature_mapping_training_samples=AM_grace_period
    learning_rate: the default stochastic gradient descent learning rate for all autoencoders in the KitNET instance.
    hidden_ratio: the default ratio of hidden to visible neurons. E.g., 0.75 will cause roughly a 25% compression in the hidden layer.
    feature_map: One may optionally provide a feature map instead of learning one. The map must be a list,
              where the i-th entry contains a list of the feature indices to be assingned to the i-th autoencoder in the ensemble.
              For example, [[2,5,3],[4,0,1],[6,7]]"""

    def __init__(self, n, max_autoencoder_size=10, feature_mapping_training_samples=None, anomaly_detector_training_samples=10000, learning_rate=0.1, hidden_ratio=0.75, feature_map=None):
        # Parameters:
        self.anomaly_detector_training_samples = anomaly_detector_training_samples
        if feature_mapping_training_samples is None:
            self.feature_mapping_training_samples = anomaly_detector_training_samples
        else:
            self.feature_mapping_training_samples = feature_mapping_training_samples
        if max_autoencoder_size <= 0:
            self.m = 1
        else:
            self.m = max_autoencoder_size
        self.learning_rate = learning_rate
        self.hidden_ratio = hidden_ratio
        self.n = n

        # Variables
        self.n_trained = 0  # the number of training instances so far
        self.n_executed = 0  # the number of executed instances so far
        self.v = feature_map
        if self.v is None:
            log.info("Feature-Mapper: train-mode, Anomaly-Detector: off-mode")
        else:
            self.__createAD__()
            log.info("Feature-Mapper: execute-mode, Anomaly-Detector: train-mode")
        # incremental feature cluatering for the feature mapping process
        self.feature_mapper = CorrelationCluster(self.n)
        self.ensemble_layer = []
        self.output_layer = None

    # If feature_mapping_training_samples+AM_grace_period has passed, then this function executes KitNET on x. Otherwise, this function learns from x.
    # x: a numpy array of length n
    # NOTE: KitNET automatically performs 0-1 normalization on all attributes
    def process(self, x):
        if self.n_trained > self.feature_mapping_training_samples + self.anomaly_detector_training_samples:  # If both the FM and AD are in execute-mode
            return self.execute(x)
        else:
            self.train(x)
            return 0.0

    # force train KitNET on x
    # returns the anomaly score of x during training (do not use for alerting)
    def train(self, x):
        # If the FM is in train-mode, and the user has not supplied a feature mapping
        if self.n_trained <= self.feature_mapping_training_samples and self.v is None:
            # update the incremental correlation matrix
            self.feature_mapper.update(x)
            if self.n_trained == self.feature_mapping_training_samples:  # If the feature mapping should be instantiated
                self.v = self.feature_mapper.cluster(self.m)
                self.__createAD__()
                log.info("The Feature-Mapper found a mapping: "+str(self.n) +
                         " features to "+str(len(self.v))+" autoencoders.")
                log.info("Feature-Mapper: execute-mode, Anomaly-Detector: train-mode")
        else:  # train
            # Ensemble Layer
            S_l1 = np.zeros(len(self.ensemble_layer))
            for a in range(len(self.ensemble_layer)):
                # make sub instance for autoencoder 'a'
                xi = x[self.v[a]]
                S_l1[a] = self.ensemble_layer[a].train(xi)
            # OutputLayer
            self.output_layer.train(S_l1)
            if self.n_trained == self.anomaly_detector_training_samples+self.feature_mapping_training_samples:
                log.info("Feature-Mapper: execute-mode, Anomaly-Detector: execute-mode")
        self.n_trained += 1

    # force execute KitNET on x
    def execute(self, x):
        if self.v is None:
            raise RuntimeError(
                'KitNET Cannot execute x, because a feature mapping has not yet been learned or provided. Try running process(x) instead.')
        else:
            self.n_executed += 1
            # Ensemble Layer
            S_l1 = np.zeros(len(self.ensemble_layer))
            for a in range(len(self.ensemble_layer)):
                # make sub inst
                xi = x[self.v[a]]
                S_l1[a] = self.ensemble_layer[a].execute(xi)
            # OutputLayer
            return self.output_layer.execute(S_l1)

    def __createAD__(self):
        # construct ensemble layer
        for map in self.v:
            params = AutoEncoderParams(n_visible=len(map), n_hidden=0, learning_rate=self.learning_rate,
                                       corruption_level=0, training_samples=0, hidden_ratio=self.hidden_ratio)
            self.ensemble_layer.append(AutoEncoder(params))

        # construct output layer
        params = AutoEncoderParams(len(self.v), n_hidden=0, learning_rate=self.learning_rate,
                                   corruption_level=0, training_samples=0, hidden_ratio=self.hidden_ratio)
        self.output_layer = AutoEncoder(params)
