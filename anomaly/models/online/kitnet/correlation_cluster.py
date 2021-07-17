#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

import numpy as np
import logging as log
from scipy.cluster.hierarchy import linkage, fcluster, to_tree


class CorrelationCluster:
    """A helper class for KitNET which performs a correlation-based incremental clustering of the dimensions in X
    n: the number of dimensions in the dataset
    For more information and citation, please see our NDSS'18 paper: Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection"""

    def __init__(self, n):
        # parameter:
        self.n = n
        # varaibles
        self.c = np.zeros(n)  # linear num of features
        self.c_r = np.zeros(n)  # linear sum of feature residules
        self.c_rs = np.zeros(n)  # linear sum of feature residules
        self.C = np.zeros((n, n))  # partial correlation matrix
        self.N = 0  # number of updates performed

    # x: a numpy vector of length n
    def update(self, x):
        self.N += 1
        self.c += x
        c_rt = x - self.c/self.N
        self.c_r += c_rt
        self.c_rs += c_rt**2
        self.C += np.outer(c_rt, c_rt)

    # creates the current correlation distance matrix between the features
    def correlationDistance(self):
        c_rs_sqrt = np.sqrt(self.c_rs)
        C_rs_sqrt = np.outer(c_rs_sqrt, c_rs_sqrt)
        # this protects against dive by zero erros (occurs when a feature is a constant)
        C_rs_sqrt[C_rs_sqrt == 0] = 1e-100
        D = 1-self.C/C_rs_sqrt  # the correlation distance matrix
        D[D < 0] = 0  # small negatives may appear due to the incremental fashion in which we update the mean. Therefore, we 'fix' them
        return D

    # clusters the features together, having no more than maxClust features per cluster
    def cluster(self, maxClust):
        D = self.correlationDistance()
        # log.info(maxClust)
        # log.info(self.n)
        distance_matrix = D[np.triu_indices(self.n, 1)]
        # distance_matrix = np.nan_to_num(distance_matrix)
        # print(np.all(np.isfinite(distance_matrix)))
        Z = linkage(distance_matrix)  # create a linkage matrix based on the distance matrix
        if maxClust < 1:
            maxClust = 1
        if maxClust > self.n:
            maxClust = self.n
        map = self.__breakClust__(to_tree(Z), maxClust)
        return map

    # a recursive helper function which breaks down the dendrogram branches until all clusters have no more than maxClust elements
    def __breakClust__(self, dendro, maxClust):
        if dendro.count <= maxClust:  # base case: we found a minimal cluster, so mark it
            return [dendro.pre_order()]  # return the origional ids of the features in this cluster
        return self.__breakClust__(dendro.get_left(), maxClust) + self.__breakClust__(dendro.get_right(), maxClust)
