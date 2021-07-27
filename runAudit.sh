#!/usr/bin/env bash

for file in /mnt/storage2/datasets/audit/labelled/*/Connection.csv
do
  echo $file
  python3 anomaly/main.py --conn $file --model gboost
done

