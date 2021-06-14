#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

import logging as log
import os
import csv
import platform
import subprocess

from scapy.all import rdpcap, sys


class TSVReader:
    """A class for reading TSVs"""

    def __init__(self, file_path, limit):
        self.file_path = file_path
        self.current_packet_index = 0
        self.limit = limit

        self.tsvin = None  # used for parsing TSV file
        self.tsvinf = None

        self.__prep__()

    def __prep__(self):
        # Find file
        if not os.path.isfile(self.file_path):  # file does not exist
            raise Exception('File {file_path} does not exist'.format(file_path=self.file_path))

        # check file type
        type = self.file_path.split('.')[-1]

        # If file is TSV (pre-parsed by wireshark script)
        if type != "tsv":
            log.error("File: " + self.file_path + " is not a tsv file")
            raise Exception()

        maxInt = sys.maxsize
        decrement = True
        while decrement:
            # decrease the maxInt value by factor 10
            # as long as the OverflowError occurs.
            decrement = False
            try:
                csv.field_size_limit(maxInt)
            except OverflowError:
                maxInt = int(maxInt / 10)
                decrement = True

        log.info("counting lines in TSV file (with tshark)...")
        num_lines = sum(1 for line in open(self.file_path))
        log.info("There are " + str(num_lines) + " packets")
        self.limit = min(self.limit, num_lines-1)
        self.tsvinf = open(self.file_path, 'rt', encoding="utf8")
        self.tsvin = csv.reader(self.tsvinf, delimiter='\t')
        row = self.tsvin.__next__()  # move iterator past header

    def get_next_row(self):
        if self.current_packet_index == self.limit:
            self.tsvinf.close()
            return []

        row = self.tsvin.__next__()

        self.current_packet_index += 1

        return row


def get_tshark_path():
    if platform.system() == 'Windows':
        return 'C:\Program Files\Wireshark\\tshark.exe'
    else:
        system_path = os.environ['PATH']
        for path in system_path.split(os.pathsep):
            filename = os.path.join(path, 'tshark')
            if os.path.isfile(filename):
                return filename
    return ''


def pcap2tsv_with_tshark(file_path):
    log.info('Converting PCAP file to TSV...')
    fields = "-e frame.time_epoch -e frame.len -e eth.src -e eth.dst -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e icmp.type -e icmp.code -e arp.opcode -e arp.src.hw_mac -e arp.src.proto_ipv4 -e arp.dst.hw_mac -e arp.dst.proto_ipv4 -e ipv6.src -e ipv6.dst"
    cmd = '"' + get_tshark_path() + '" -r ' + file_path + ' -T fields ' + \
        fields + ' -E header=y -E occurrence=f > '+file_path+".tsv"
    subprocess.call(cmd, shell=True)
    log.info("tshark parsing complete. File saved as: "+file_path + ".tsv")
