#!/bin/bash

set -eux pipefail

netflow_estimators=(5 10 15)
netflow_lrate=(0.05 0.075 0.1)

# change netflow estimators
for estimator in ${netflow_estimators[@]}; do
  echo ${estimator}
  sed -i "s/n_estimators': .*/n_estimators': ${estimator},/g" anomaly/models/offline/gradient_boost.py
  ./runNetflow.sh
done

# change netflow learning rate
for lrate in ${netflow_lrate[@]}; do
  echo ${lrate}
  sed -i "s/learning_rate': .*/learning_rate': ${lrate},/g" anomaly/models/offline/gradient_boost.py
  ./runNetflow.sh
done
mv results.csv resultsNetflow.csv

audit_estimators=(5 10 15)
audit_lrate=(0.05 0.075 0.1)

# change netflow estimators
for estimator in ${audit_estimators[@]}; do
  sed -i "s/n_estimators': .*/n_estimators': ${estimator},/g" anomaly/models/offline/gradient_boost.py
  ./runAudit.sh
done

# change netflow learning rate
for lrate in ${audit_lrate[@]}; do
  sed -i "s/learning_rate': .*/learning_rate': ${lrate},/g" anomaly/models/offline/gradient_boost.py
  ./runAudit.sh
done
mv results.csv resultsAudit.csv
