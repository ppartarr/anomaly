#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

import numpy as np
import os
import subprocess
from .incremental import StatisticsDB


class NetworkStatistics:
    """Class to efficiently store network statistic queries
    HostLimit: no more that this many Host identifiers will be tracked
    HostSimplexLimit: no more that this many outgoing channels from each host will be tracked (purged periodically)
    Lambdas: a list of 'window sizes' (decay factors) to track for each stream. nan resolved to default [5,3,1,.1,.01]
    """

    def __init__(self, Lambdas=np.nan, HostLimit=255, HostSimplexLimit=1000):
        # Lambdas
        if np.isnan(Lambdas):
            self.Lambdas = [5, 3, 1, .1, .01]
        else:
            self.Lambdas = Lambdas

        # HT Limits
        self.HostLimit = HostLimit
        self.SessionLimit = HostSimplexLimit*self.HostLimit*self.HostLimit  # *2 since each dual creates 2 entries in memory
        self.MAC_HostLimit = self.HostLimit*10

        # HTs
        self.HostHostJitter = StatisticsDB(limit=self.HostLimit*self.HostLimit)  # Host to host jitter stats
        self.MACandIP = StatisticsDB(limit=self.MAC_HostLimit)                  # MAC & IP relationships
        self.Host = StatisticsDB(limit=self.HostLimit)                          # Source host bandwidth stats
        self.Port = StatisticsDB(limit=self.SessionLimit)                       # Source host session stats

    def update_get_stats(self, IPtype, srcMAC, dstMAC, srcIP, srcProtocol, dstIP, dstProtocol, datagramSize, timestamp):
        # MAC-IP: Stats on src MAC-IP relationships
        MACandIP = np.zeros((3*len(self.Lambdas,)))
        for i in range(len(self.Lambdas)):
            MACandIP[(i*3):((i+1)*3)] = self.MACandIP.update_get_1D_stats(srcMAC +
                                                                          srcIP, timestamp, datagramSize, self.Lambdas[i])

        # Host-Host BW: Stats on the dual traffic behavior between srcIP and dstIP
        HostHost = np.zeros((7*len(self.Lambdas,)))
        for i in range(len(self.Lambdas)):
            HostHost[(i*7):((i+1)*7)] = self.Host.update_get_1D2D_stats(srcIP,
                                                                        dstIP, timestamp, datagramSize, self.Lambdas[i])

        # Host-Host Jitter
        HostHostJitter = np.zeros((3*len(self.Lambdas,)))
        for i in range(len(self.Lambdas)):
            HostHostJitter[(i*3):((i+1)*3)] = self.HostHostJitter.update_get_1D_stats(srcIP +
                                                                                      dstIP, timestamp, 0, self.Lambdas[i], isTypeDiff=True)

        # Host-Host BW: Stats on the dual traffic behavior between srcIP and dstIP
        PortPort = np.zeros((7*len(self.Lambdas,)))
        if srcProtocol == 'arp':
            for i in range(len(self.Lambdas)):
                PortPort[(i*7):((i+1)*7)] = self.Port.update_get_1D2D_stats(srcMAC,
                                                                            dstMAC, timestamp, datagramSize, self.Lambdas[i])
        else:  # some other protocol (e.g. TCP/UDP)
            for i in range(len(self.Lambdas)):
                PortPort[(i*7):((i+1)*7)] = self.Port.update_get_1D2D_stats(srcIP + srcProtocol,
                                                                            dstIP + dstProtocol, timestamp, datagramSize, self.Lambdas[i])

        return np.concatenate((MACandIP, HostHost, HostHostJitter, PortPort))

    def get_net_stat_headers(self):
        MACandIP_headers = []
        Host_headers = []
        HostHost_headers = []
        HostHostJitter_headers = []
        PortPort_headers = []

        for i in range(len(self.Lambdas)):
            MACandIP_headers += ["MACandIP_"+h for h in self.MACandIP.get_headers_1D(Lambda=self.Lambdas[i], ID=None)]
            HostHost_headers += ["HostHost_" +
                                 h for h in self.Host.get_headers_1D2D(Lambda=self.Lambdas[i], IDs=None, ver=2)]
            HostHostJitter_headers += ["HostHostJitter_" +
                                       h for h in self.HostHostJitter.get_headers_1D(Lambda=self.Lambdas[i], ID=None)]
            PortPort_headers += ["PortPort_" +
                                 h for h in self.Port.get_headers_1D2D(Lambda=self.Lambdas[i], IDs=None, ver=2)]
        return MACandIP_headers + Host_headers + HostHost_headers + HostHostJitter_headers + PortPort_headers
