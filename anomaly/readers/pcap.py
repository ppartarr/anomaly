#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

import logging as log
import os
import csv
import platform
import subprocess

from scapy.all import rdpcap, sys


class PCAPReader:
    """A class for reading PCAPs"""

    def __init__(self, file_path, limit):
        self.file_path = file_path
        self.current_packet_index = 0
        self.limit = limit
        self.scapyin = None  # used for parsing pcap with scapy

        self.__prep__()

    def __prep__(self):
        # Find file
        if not os.path.isfile(self.file_path):  # file does not exist
            raise Exception('File {file_path} does not exist'.format(file_path=self.file_path))

        # check file type
        type = self.file_path.split('.')[-1]

        if type == 'pcap' or type == 'pcapng':
            log.info("counting lines in PCAP file (with scapy)...")
            self.scapyin = rdpcap(self.file_path)
            self.limit = len(self.scapyin)
            log.info("Loaded " + str(len(self.scapyin)) + " packets")
        else:
            log.error("File: " + self.file_path + " is not a pcap or pcapng file")
            raise Exception()

    def get_next_row(self):
        if self.current_packet_index == self.limit:
            return []

        row = self.scapyin[self.current_packet_index]

        self.current_packet_index += 1

        return row
