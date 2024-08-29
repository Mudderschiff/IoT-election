#!/bin/bash

# Internet sharing from the same WiFi interface. SSID=esp32 PW=election
sudo create_ap wlan0 wlan0 esp32 election &

# Run mqtt Broker
mosquitto -c config/mosquitto.conf &

# Run node-red
node-red &

conda activate myenv &
python election.py &
