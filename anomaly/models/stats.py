#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8
from sklearn.feature_selection import SelectKBest
from sklearn.metrics import roc_auc_score, f1_score
import logging as log
import numpy as np
from scipy.stats import norm

from matplotlib import pyplot as plt
from matplotlib import cm


def find_best_features(x, x_train, y_train):
    select = SelectKBest(k=30)
    selected_features = select.fit(x_train, y_train)
    indices_selected = selected_features.get_support(indices=True)
    col_names_selected = [x.columns[i] for i in indices_selected]
    return col_names_selected


def print_stats_labelled(y, guesses, y_test):
    """Statistics for labelled data"""
    log.info('guess percentage of anomalies: {percentage:.2f}'.format(
        percentage=(100 * np.count_nonzero(guesses == -1)) / len(guesses)))
    log.info('actual percentage of anomalies: {percentage:.2f}'.format(
        percentage=(100 - (100 * (y.value_counts()[1])) / len(y))))

    # ROC AUC score is not defined if there is only one class in y_true
    if len(y_test.value_counts()) > 1:
        auc = roc_auc_score(y_test, guesses)
        log.info('area under the curve: {auc}'.format(auc=auc))

    f1 = f1_score(y_true=y_test, y_pred=guesses, average='micro')
    log.info('f1 score: {f1}'.format(f1=f1))


def print_stats_unlabelled(y, guesses):
    """Statistics for unlabelled data"""
    log.info('guess percentage of anomalies: {percentage:.2f}'.format(
        percentage=(100 * np.count_nonzero(guesses == -1)) / len(guesses)))


def plot(model, file_name, root_mean_squared_errors, benign_sample, log_probs, anomaly_detector_training_samples, feature_mapping_training_samples=0):
    # plot the RMSE anomaly scores
    log.info("Plotting results")
    plt.figure(figsize=(10, 5))
    fig = plt.scatter(
        range(feature_mapping_training_samples +
              anomaly_detector_training_samples+1, len(root_mean_squared_errors)),
        root_mean_squared_errors[feature_mapping_training_samples+anomaly_detector_training_samples+1:],
        s=0.1,
        c=log_probs[feature_mapping_training_samples+anomaly_detector_training_samples+1:],
        cmap='RdYlGn')
    plt.yscale("log")
    plt.title("Anomaly Scores from " + model + "'s Execution Phase")
    plt.ylabel("RMSE (log scaled)")
    plt.xlabel("Packet number")
    figbar = plt.colorbar()
    figbar.ax.set_ylabel('Log Probability\n ', rotation=270)
    plt.show()
    fig.save
