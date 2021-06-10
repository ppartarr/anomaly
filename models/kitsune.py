#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

from .kitnet.extractors.raw_packets import RawPacketFeatureExtractor
from .kitnet.extractors.connections import ConnectionFeatureExtractor
from .kitnet.kitnet import KitNET
import logging as log
import socket


class Kitsune:
    def __init__(self, file_path, socket, limit, max_autoencoder_size=10, feature_mapping_training_samples=None, anomaly_detector_training_samples=10000, learning_rate=0.1, hidden_ratio=0.75, feature_extractor=RawPacketFeatureExtractor):
        # NOTE: read from file OR socket
        if file_path and socket:
            raise Exception('Only specify one of file_path or socket')
        elif file_path is None and socket is None:
            raise Exception('Requires one of file_path or socket')

        self.file_path = file_path
        self.socket = socket

        self.feature_extractor = feature_extractor(file_path, socket, limit)

        # init Kitnet
        self.anomaly_detector = KitNET(self.feature_extractor.get_num_features(), max_autoencoder_size,
                                       feature_mapping_training_samples, anomaly_detector_training_samples, learning_rate, hidden_ratio)

    def proc_next_packet(self):
        # if self.file_path:
        # create feature vector
        x = self.feature_extractor.get_next_vector()
        if len(x) == 0:
            return -1  # Error or no packets left
        # elif self.socket:
        #     x = self.feature_extractor.

        # process KitNET
        return self.anomaly_detector.process(x)  # will train during the grace periods, then execute on all the rest.

    def run(self):
        root_mean_squared_errors = []
        i = 0
        if self.file_path:
            while True:
                i += 1
                if i % 1000 == 0:
                    log.info(i)
                rmse = self.proc_next_packet()
                if rmse == -1:
                    break
                root_mean_squared_errors.append(rmse)
        elif self.socket:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            sock.bind('/tmp/{socket_name}'.format(socket_name=self.feature_extractor.SOCKET_NAME))
            root_mean_squared_errors = []
            i = 0
            while True:
                datagram = sock.recv(1024)
                if datagram:
                    print(datagram)
                    i += 1
                    if i % 1000 == 0:
                        log.info(i)
                    rmse = self.proc_next_packet()
                    if rmse == -1:
                        break
                    root_mean_squared_errors.append(rmse)
