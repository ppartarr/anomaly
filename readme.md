# Anomaly based Network Intrusion Detection :bug:

## Setup guide
Start by installing the dependencies in a python virtual environment to avoid dependency hell with other python projects

```bash
pip3 install virtualenv
virtualenv venv
. venv/bin/activate
pip3 install -r requirements
```

## Run
We are using argparse, here is an example of how to run the script:
```bash
python3 anomaly.py --data ./data/Friday-02-03-2018_TrafficForML_CICFlowMeter.csv
```

## Anomaly count
```bash
λ  philippe@srv11013 9:22:48  /mnt/storage/ids-2018/dataset  python3 stats.py --dir Processed\ Traffic\ Data\ for\ ML\ Algorithms
Processed Traffic Data for ML Algorithms/Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv percentage of malicious flows: 190.5984208761394
Processed Traffic Data for ML Algorithms/Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv percentage of malicious flows: 5.270476077652631
Processed Traffic Data for ML Algorithms/Friday-02-03-2018_TrafficForML_CICFlowMeter.csv percentage of malicious flows: 37.53895674620664
sys:1: DtypeWarning: Columns (0,1,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78) have mixed types.Specify dtype option on import or set low_memory=False.
Processed Traffic Data for ML Algorithms/Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv percentage of malicious flows: 39.10652545612657
Processed Traffic Data for ML Algorithms/Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv percentage of malicious flows: 57.06024031418788
Processed Traffic Data for ML Algorithms/Friday-16-02-2018_TrafficForML_CICFlowMeter.csv percentage of malicious flows: 134.70024979184015
Processed Traffic Data for ML Algorithms/Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv percentage of malicious flows: 12.661521499448734
Processed Traffic Data for ML Algorithms/Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv percentage of malicious flows: 0.03453496569876542
Processed Traffic Data for ML Algorithms/Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv percentage of malicious flows: 7.815348189237466
Processed Traffic Data for ML Algorithms/Friday-23-02-2018_TrafficForML_CICFlowMeter.csv percentage of malicious flows: 0.05400716978575566
total percentage of malicious flows: 20.380819517930977
```

## Best K features (k=30)
```bash
['Protocol', 'Flow Duration', 'Fwd Pkt Len Min', 'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean', 'Bwd Pkt Len Std', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Fwd IAT Tot', 'Fwd IAT Mean', 'Fwd IAT Max', 'Bwd IAT Tot', 'Bwd IAT Std', 'Pkt Len Min', 'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Var', 'RST Flag Cnt', 'ACK Flag Cnt', 'ECE Flag Cnt', 'Pkt Size Avg', 'Bwd Seg Size Avg', 'Init Bwd Win Byts', 'Fwd Seg Size Min', 'Idle Mean', 'Idle Max', 'Idle Min']
```