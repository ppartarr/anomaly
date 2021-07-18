#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8
from sklearn.feature_selection import SelectKBest
from sklearn.metrics import roc_auc_score, f1_score, confusion_matrix
import logging as log
import numpy as np
import os
import anomaly.config as config
from scipy.stats import norm

from matplotlib import pyplot as plt
from matplotlib import cm


def find_best_features(x, x_train, y_train):
    select = SelectKBest(k=40)
    selected_features = select.fit(x_train, y_train)
    indices_selected = selected_features.get_support(indices=True)
    col_names_selected = [x.columns[i] for i in indices_selected]
    return col_names_selected


def print_stats_labelled(y, guesses, y_true, model, params):
    """Statistics for labelled data"""
    log.info('guess percentage of anomalies: {percentage:.2f}'.format(
        percentage=(100 * np.count_nonzero(guesses == -1)) / len(guesses)))
    log.info('actual percentage of anomalies: {percentage:.2f}'.format(
        percentage=(100 - (100 * (y_true.value_counts()[1])) / len(y_true))))

    # ROC AUC score is not defined if there is only one class in y_true
    if len(y_true.value_counts()) > 1:
        auc = roc_auc_score(y_true, guesses)
        log.info('area under the curve: {auc}'.format(auc=auc))

    f1 = f1_score(y_true=y_true, y_pred=guesses, average='micro')
    log.info('f1 score: {f1}'.format(f1=f1))

    y_true = y_true.to_numpy()

    cm = confusion_matrix(y_true, guesses)

    tp = cm[1][1]
    tn = cm[0][0]
    fp = cm[0][1]
    fn = cm[1][0]

    log.info('true positives {tp}'.format(tp=tp))
    log.info('true negatives {tn}'.format(tn=tn))
    log.info('false positives {fp}'.format(fp=fp))
    log.info('false negatives {fn}'.format(fn=fn))

    save_stats(f1, auc, tp, tn, fp, fn, model, params)


def save_stats(f1, auroc, tp, tn, fp, fn, model, params):
    header = 'Model,Params,F1,AUROC,True Positives,True Negatives,False Positives,False Negatives,Precision,Recall\n'

    # calculate recall and precision
    precision = tp / (tp + fp)
    recall = tp / (tp + fn)

    result = '{model},{f1},{auroc},{tp},{tn},{fp},{fn},{precision},{recall},{params}\n'.format(
        model=model,
        f1=f1,
        auroc=auroc,
        tp=tp,
        tn=tn,
        fp=fp,
        fn=fn,
        precision=precision,
        recall=recall,
        params=params)

    if os.path.isfile(config.results_file_path):
        f = open(config.results_file_path, 'a')
        f.write(result)
    else:
        f = open(config.results_file_path, 'w+')
        f.write(header)
        f.write(result)

    f.close()
    log.info('Results saved to {f}'.format(f=config.results_file_path))


def count_false_positives(guesses, y_true):
    fp = 0
    for index, _ in np.ndenumerate(guesses):
        if guesses[index[0]] == 1 and (y_true[index[0]] == -1 or y_true[index[0]] == 0):
            fp += 1
    return fp


def count_false_negatives(guesses, y_true):
    fn = 0
    for index, _ in np.ndenumerate(guesses):
        if (guesses[index[0]] == -1 or guesses[index[0]] == 0) and y_true[index[0]] == 1:
            fn += 1
    return fn


def print_stats_online(y_true, guesses):
    """Statistics for online models"""
    y_true = np.array(y_true)
    guesses = np.array(guesses)
    num_anoms = np.count_nonzero(guesses == 1)
    log.info('guess percentage of anomalies: {percentage:.2f}'.format(
        percentage=(num_anoms / len(guesses))))

    # ROC AUC score is not defined if there is only one class in y_true
    if 0 in y_true and 1 in y_true:
        auc = roc_auc_score(y_true, guesses)
        log.info('area under the curve: {auc}'.format(auc=auc))

    f1 = f1_score(y_true=y_true, y_pred=guesses, average='micro')
    log.info('f1 score: {f1}'.format(f1=f1))

    log.info(len(guesses))
    log.info(guesses)
    log.info(len(y_true))
    log.info(y_true)

    cm = confusion_matrix(y_true, guesses)

    tp = cm[1][1]
    tn = cm[0][0]
    fp = cm[0][1]
    fn = cm[1][0]

    log.info('true positives {tp}'.format(tp=tp))
    log.info('true negatives {tn}'.format(tn=tn))
    log.info('false positives {fp}'.format(fp=fp))
    log.info('false negatives {fn}'.format(fn=fn))

    save_stats(f1, auc, tp, tn, fp, fn)


def plot(model, file_name, root_mean_squared_errors, benign_sample, log_probs, anomaly_detector_training_samples, feature_mapping_training_samples=0):
    # plot the RMSE anomaly scores
    log.info("Plotting results")

    plt.figure(figsize=(10, 5))
    fig = plt.scatter(
        range(
            feature_mapping_training_samples + anomaly_detector_training_samples+1,
            len(root_mean_squared_errors)),
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
    plt.savefig(file_name)
    log.info('Saved plot as {plt}'.format(plt=file_name))
    plt.show()
