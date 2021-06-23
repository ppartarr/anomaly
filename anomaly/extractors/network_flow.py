#!/home/philippe/src/anomaly/venv/bin/python3
# coding: utf-8

import logging as log
import numpy as np

from anomaly.utils import mac_to_decimal, ipv4_to_decimal, ipv6_to_decimal, convert_ip_address_to_decimal

from anomaly.readers.socket import SocketReader


class NetworkFlowFeatureExtractor:
    def __init__(self, path, reader, limit=np.inf, encoded=False, labelled=False):
        self.path = path
        self.reader = reader(path, limit)
        self.limit = limit
        self.encoded = encoded

        # skip comment & header if reading from netcap audit record csv
        if isinstance(self.reader, SocketReader):
            self.reader.get_next_row()
            self.reader.get_next_row()

    def get_num_features(self):
        num_features = 81

        log.info('There are {num_headers} features'.format(num_headers=num_features))
        return num_features

    def get_next_vector(self):
        row = self.reader.get_next_row()
        if row == []:
            return []

        banned = [np.inf, np.nan, -np.inf]
        for value in banned:
            if value in row:
                self.reader.get_next_row()

        network_flow = {
            # 'Flow ID': row[0],
            'Src IP': convert_ip_address_to_decimal(row[1]),
            'Src Port': row[2],
            'Dst IP': convert_ip_address_to_decimal(row[3]),
            'Dst Port': row[4],
            'Protocol': row[5],
            # 'Timestamp': row[6],
            'Flow Duration': row[7],
            'Tot Fwd Pkts': row[8],
            'Tot Bwd Pkts': row[9],
            'TotLen Fwd Pkts': row[10],
            'TotLen Bwd Pkts': row[11],
            'Fwd Pkt Len Max': row[12],
            'Fwd Pkt Len Min': row[13],
            'Fwd Pkt Len Mean': row[14],
            'Fwd Pkt Len Std': row[15],
            'Bwd Pkt Len Max': row[16],
            'Bwd Pkt Len Min': row[17],
            'Bwd Pkt Len Mean': row[18],
            'Bwd Pkt Len Std': row[19],
            'Flow Byts/s': row[20],
            'Flow Pkts/s': row[21],
            'Flow IAT Mean': row[22],
            'Flow IAT Std': row[23],
            'Flow IAT Max': row[24],
            'Flow IAT Min': row[25],
            'Fwd IAT Tot': row[26],
            'Fwd IAT Mean': row[27],
            'Fwd IAT Std': row[28],
            'Fwd IAT Max': row[29],
            'Fwd IAT Min': row[30],
            'Bwd IAT Tot': row[31],
            'Bwd IAT Mean': row[32],
            'Bwd IAT Std': row[33],
            'Bwd IAT Max': row[34],
            'Bwd IAT Min': row[35],
            'Fwd PSH Flags': row[36],
            'Bwd PSH Flags': row[37],
            'Fwd URG Flags': row[38],
            'Bwd URG Flags': row[39],
            'Fwd Header Len': row[40],
            'Bwd Header Len': row[41],
            'Fwd Pkts/s': row[42],
            'Bwd Pkts/s': row[43],
            'Pkt Len Min': row[44],
            'Pkt Len Max': row[45],
            'Pkt Len Mean': row[46],
            'Pkt Len Std': row[47],
            'Pkt Len Var': row[48],
            'FIN Flag Cnt': row[49],
            'SYN Flag Cnt': row[50],
            'RST Flag Cnt': row[51],
            'PSH Flag Cnt': row[52],
            'ACK Flag Cnt': row[53],
            'URG Flag Cnt': row[54],
            'CWE Flag Count': row[55],
            'ECE Flag Cnt': row[56],
            'Down/Up Ratio': row[57],
            'Pkt Size Avg': row[58],
            'Fwd Seg Size Avg': row[59],
            'Bwd Seg Size Avg': row[60],
            'Fwd Byts/b Avg': row[61],
            'Fwd Pkts/b Avg': row[62],
            'Fwd Blk Rate Avg': row[63],
            'Bwd Byts/b Avg': row[64],
            'Bwd Pkts/b Avg': row[65],
            'Bwd Blk Rate Avg': row[66],
            'Subflow Fwd Pkts': row[67],
            'Subflow Fwd Byts': row[68],
            'Subflow Bwd Pkts': row[69],
            'Subflow Bwd Byts': row[70],
            'Init Fwd Win Byts': row[71],
            'Init Bwd Win Byts': row[72],
            'Fwd Act Data Pkts': row[73],
            'Fwd Seg Size Min': row[74],
            'Active Mean': row[75],
            'Active Std': row[76],
            'Active Max': row[77],
            'Active Min': row[78],
            'Idle Mean': row[79],
            'Idle Std': row[80],
            'Idle Max': row[81],
            'Idle Min': row[82]
            # 'Label': row[83]
        }

        return np.fromiter(network_flow.values(), dtype=float)
