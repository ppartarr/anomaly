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
python3 --data ./data/Friday-02-03-2018_TrafficForML_CICFlowMeter.csv
```