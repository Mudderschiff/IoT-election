#!/bin/bash

source ~/miniconda3/etc/profile.d/conda.sh
conda activate myenv

python -m election.py &

# Get the PID of the last background command
#PID=$!
# Plot the CPU and memory usage of the process
#psrecord $PID --plot plot.png 
