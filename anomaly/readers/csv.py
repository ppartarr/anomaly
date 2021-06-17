#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

import logging as log
import os
import csv


class CSVReader:
    """A class for reading CSVs"""

    def __init__(self, file_path, limit):
        self.file_path = file_path
        self.current_packet_index = 0
        self.limit = limit

        self.__prep__()

    def __prep__(self):
        # Find file
        if not os.path.isfile(self.file_path):  # file does not exist
            raise Exception('File {file_path} does not exist'.format(file_path=self.file_path))

        # check file type
        type = self.file_path.split('.')[-1]

        if type == "csv":
            # NOTE: if overflowing, re-introduce maxInt from kitsune
            log.info("Counting lines in CSV file...")
            num_lines = sum(1 for line in open(self.file_path))
            log.info('There are {num_lines} packets'.format(num_lines=num_lines))
            self.limit = min(self.limit, num_lines-1)
            self.csv_stream = open(self.file_path, 'rt', encoding="utf8")
            self.csv_iterator = csv.reader(self.csv_stream)
            # NOTE: move iterator past comment
            row = self.csv_iterator.__next__()

            # NOTE: move iterator past header
            row = self.csv_iterator.__next__()
            self.current_packet_index + 2

        else:
            raise Exception('File {file_path} is not a csv file'.format(file_path=self.file_path))

    def get_next_row(self):
        if self.current_packet_index == (self.limit - 1):
            self.csv_stream.close()
            return []

        row = self.csv_iterator.__next__()

        self.current_packet_index += 1

        return row
