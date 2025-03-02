#!/bin/bash

source ~/miniconda3/etc/profile.d/conda.sh
conda activate myenv

python -m election.py &

# Get the PID of the last background command
PID=$!

# Monitor the program with collectl. every 100 milliseconds
collectl -scm -P $PID -oT -i 0.1 -f usage_data