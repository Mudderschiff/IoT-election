#!/bin/bash

# Run mqtt Broker
mosquitto -c config/mosquitto.conf &

# Run node-red
node-red &