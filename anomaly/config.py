#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

import numpy as np

auto_encoder = {
    'packet_limit': np.inf,                     # the max number of data points to process
    'max_autoencoders': 10,                    # max size for any autoencoder
    'feature_mapping_training_samples': 10000,  # number of instances taken to learn the feature mapping
    'anomaly_detector_training_samples': 10000  # the number of instances taken to train the ensemble
}

hstree = {
    'packet_limit': 10000,                     # the max number of data points to process
    'anomaly_detector_training_samples': 5000  # the number of instances taken to train the ensemble
}

# for iForest & LOF & IGBoost
# joblib: By default all available workers will be used (``n_jobs=-1``) unless the
#     caller passes an explicit value for the ``n_jobs`` parameter.
n_jobs = -1

# reading from csv & pcaps
chunksize = 500000
blocksize = '16MB'
memory_limit = '1GB'
n_workers = 4
threads_per_worker = 4

# logging & results
log_file_path = "anomaly.log"
results_file_path = "results.csv"
