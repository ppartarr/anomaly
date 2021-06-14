#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

import numpy as np

auto_encoder = {
    'packet_limit': 10000,                       # the max number of data points to process
    'max_autoencoders': 10,                      # max size for any autoencoder
    'feature_mapping_training_samples': 5000,    # number of instances taken to learn the feature mapping
    'anomaly_detector_training_samples': 5000  # the number of instances taken to train the ensemble
}

# for iForest & LOF
n_jobs = -1

# reading from csv & pcaps
chunksize = 500000
