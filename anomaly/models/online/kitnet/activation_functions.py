#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

import numpy as np
from scipy.stats import norm
np.seterr(all='ignore')


def pdf(x, mu, sigma):  # normal distribution pdf
    x = (x-mu)/sigma
    return np.exp(-x**2/2)/(np.sqrt(2*np.pi)*sigma)


def invLogCDF(x, mu, sigma):  # normal distribution cdf
    x = (x - mu) / sigma
    return norm.logcdf(-x)  # note: we mutiple by -1 after normalization to better get the 1-cdf


def sigmoid(x):
    return 1. / (1 + np.exp(-x))


def dsigmoid(x):
    return x * (1. - x)


def tanh(x):
    return np.tanh(x)


def dtanh(x):
    return 1. - x * x


def softmax(x):
    e = np.exp(x - np.max(x))  # prevent overflow
    if e.ndim == 1:
        return e / np.sum(e, axis=0)
    else:
        return e / np.array([np.sum(e, axis=1)]).T  # ndim = 2


def ReLU(x):
    return x * (x > 0)


def dReLU(x):
    return 1. * (x > 0)


class rollmean:
    def __init__(self, k):
        self.winsize = k
        self.window = np.zeros(self.winsize)
        self.pointer = 0

    def apply(self, newval):
        self.window[self.pointer] = newval
        self.pointer = (self.pointer+1) % self.winsize
        return np.mean(self.window)

# probability density for the Gaussian dist
# def gaussian(x, mean=0.0, scale=1.0):
#     s = 2 * np.power(scale, 2)
#     e = np.exp( - np.power((x - mean), 2) / s )

#     return e / np.square(np.pi * s)
