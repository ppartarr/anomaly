#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

import logging as log
import os
import csv
import socket


class SocketReader:
    """A class for reading from a Unix socket"""

    def __init__(self, path, limit):
        self.path = path
        self.current_packet_index = 0
        self.limit = limit
        self.buffer_size = 1024

        self.sock = None

        self.__prep__()

    def __prep__(self):
        if os.path.exists(self.path):
            os.remove(self.path)

        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.sock.bind(self.path)

        log.info("starting to read from %s", self.path)

    def get_next_row(self):
        if self.current_packet_index == self.limit:
            return []

        row = self.sock.recv(self.buffer_size)
        if row:
            row = row.decode('utf-8').split(',')
            self.current_packet_index += 1
            return row
