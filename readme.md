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

## Dataset
We are using a dataset purpose-built for training Intrusion Detection Systems published by the Canadian Institute for Cybersecurity: https://www.unb.ca/cic/datasets/ids-2018.html

### Anomaly count
The [stats.py](stats.py) script will calculates the number of labelled anomalies in the dataset and calculates the total percentage accross the dataset
```bash
root@srv11013:/mnt/storage/ids-2018/dataset# python3 stats.py --dir Processed\ Traffic\ Data\ for\ ML\ Algorithms/
Processed Traffic Data for ML Algorithms/Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv percentage of malicious flows: 65.5882507212169
Processed Traffic Data for ML Algorithms/Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv percentage of malicious flows: 5.00660420093937
Processed Traffic Data for ML Algorithms/Thursday-20-02-2018_TrafficForML_CICFlowMeter.csv percentage of malicious flows: 7.24882711088589
Processed Traffic Data for ML Algorithms/Friday-02-03-2018_TrafficForML_CICFlowMeter.csv percentage of malicious flows: 27.293326657606755
Processed Traffic Data for ML Algorithms/Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv percentage of malicious flows: 28.112646281615707
Processed Traffic Data for ML Algorithms/Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv percentage of malicious flows: 36.33016236320721
Processed Traffic Data for ML Algorithms/Friday-16-02-2018_TrafficForML_CICFlowMeter.csv percentage of malicious flows: 57.39246119733925
Processed Traffic Data for ML Algorithms/Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv percentage of malicious flows: 11.238550066546622
Processed Traffic Data for ML Algorithms/Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv percentage of malicious flows: 0.03452304317764585
Processed Traffic Data for ML Algorithms/Friday-23-02-2018_TrafficForML_CICFlowMeter.csv percentage of malicious flows: 0.05397801778604296
total percentage of malicious flows: 10.190409758965489
```

### Best K features (k=30)
```bash
['Protocol', 'Flow Duration', 'Fwd Pkt Len Min', 'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean', 'Bwd Pkt Len Std', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Fwd IAT Tot', 'Fwd IAT Mean', 'Fwd IAT Max', 'Bwd IAT Tot', 'Bwd IAT Std', 'Pkt Len Min', 'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Var', 'RST Flag Cnt', 'ACK Flag Cnt', 'ECE Flag Cnt', 'Pkt Size Avg', 'Bwd Seg Size Avg', 'Init Bwd Win Byts', 'Fwd Seg Size Min', 'Idle Mean', 'Idle Max', 'Idle Min']
```