#!/usr/bin/env bash

for file in /mnt/storage2/datasets/netflow/*.csv
do
  echo $file
  python3 anomaly/main.py --csv $file --model gboost
done

