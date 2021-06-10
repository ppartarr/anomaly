#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

from .activation_functions import sigmoid

import sys
import numpy as np
import json


class AutoEncoderParams:
    def __init__(self, n_visible=5, n_hidden=3, learning_rate=0.001, corruption_level=0.0, training_samples=10000, hidden_ratio=None):
        self.n_visible = n_visible  # num of units in visible (input) layer
        self.n_hidden = n_hidden  # num of units in hidden layer
        self.learning_rate = learning_rate
        self.corruption_level = corruption_level
        self.training_samples = training_samples
        self.hidden_ratio = hidden_ratio


class AutoEncoder:
    def __init__(self, params):
        self.params = params

        if self.params.hidden_ratio is not None:
            self.params.n_hidden = int(np.ceil(self.params.n_visible*self.params.hidden_ratio))

        # for 0-1 normlaization
        self.norm_max = np.ones((self.params.n_visible,)) * -np.Inf
        self.norm_min = np.ones((self.params.n_visible,)) * np.Inf
        self.n = 0

        self.rng = np.random.RandomState(1234)

        a = 1. / self.params.n_visible
        self.W = np.array(self.rng.uniform(  # initialize W uniformly
            low=-a,
            high=a,
            size=(self.params.n_visible, self.params.n_hidden)))

        self.hbias = np.zeros(self.params.n_hidden)  # initialize h bias 0
        self.vbias = np.zeros(self.params.n_visible)  # initialize v bias 0
        self.W_prime = self.W.T

    def get_corrupted_input(self, input, corruption_level):
        assert corruption_level < 1

        return self.rng.binomial(size=input.shape,
                                 n=1,
                                 p=1 - corruption_level) * input

    # Encode
    def get_hidden_values(self, input):
        return sigmoid(np.dot(input, self.W) + self.hbias)

    # Decode
    def get_reconstructed_input(self, hidden):
        return sigmoid(np.dot(hidden, self.W_prime) + self.vbias)

    def train(self, x):
        self.n = self.n + 1
        # update norms
        self.norm_max[x > self.norm_max] = x[x > self.norm_max]
        self.norm_min[x < self.norm_min] = x[x < self.norm_min]

        # 0-1 normalize
        x = (x - self.norm_min) / (self.norm_max - self.norm_min + 0.0000000000000001)

        if self.params.corruption_level > 0.0:
            tilde_x = self.get_corrupted_input(x, self.params.corruption_level)
        else:
            tilde_x = x
        y = self.get_hidden_values(tilde_x)
        z = self.get_reconstructed_input(y)

        L_h2 = x - z
        L_h1 = np.dot(L_h2, self.W) * y * (1 - y)

        L_vbias = L_h2
        L_hbias = L_h1
        L_W = np.outer(tilde_x.T, L_h1) + np.outer(L_h2.T, y)

        self.W += self.params.learning_rate * L_W
        self.hbias += self.params.learning_rate * L_hbias
        self.vbias += self.params.learning_rate * L_vbias
        return np.sqrt(np.mean(L_h2**2))  # the RMSE reconstruction error during training

    def reconstruct(self, x):
        y = self.get_hidden_values(x)
        z = self.get_reconstructed_input(y)
        return z

    def execute(self, x):  # returns MSE of the reconstruction of x
        if self.n < self.params.training_samples:
            return 0.0
        else:
            # 0-1 normalize
            x = (x - self.norm_min) / (self.norm_max - self.norm_min + 0.0000000000000001)
            z = self.reconstruct(x)
            rmse = np.sqrt(((x - z) ** 2).mean())  # MSE
            return rmse

    def inGrace(self):
        return self.n < self.params.training_samples
