# Anomaly based Network Intrusion Detection :bug:

## Setup guide
Start by installing the dependencies in a python virtual environment to avoid dependency hell with other python projects

```bash
pip3 install virtualenv
virtualenv venv
. venv/bin/activate
pip3 install -r requirements
```

### Set the PYTHONPATH
**Question: I'm getting `ModuleNotFoundError: No module named 'anomaly'` when running the program**
Answer: Set the python path as shown below
```bash
export PYTHONPATH=`/path/to/project/root
```

## Run
We are using argparse, here is an example of how to run the script:
```bash
python3 anomaly.py --data ./data/Friday-02-03-2018_TrafficForML_CICFlowMeter.csv
```

# Key performance modifications

## Convert .csv files to .parquet

```bash
$ python3 anomaly/convert.py -h
usage: convert.py [-h] [--dir DIR] [--csv CSV] [--out OUT]

Anomaly-based Network Intrusion Detection

optional arguments:
  -h, --help  show this help message and exit
  --dir DIR   directory containing the network flow csvs
  --csv CSV   csv file containing network flow csvs
  --out OUT   parquet output directory
```

## Memory
* change the `chunksize` in the pandas `read_csv` call
* change the type of the columns in column.py

## Threads
* some models e.g. iForest can be parallelised by specifying `n_jobs=-1` to use all available cores