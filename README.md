# IoT Election

## Devices
| Device | Role |
| ------ | ---- |
| Laptop | Encryption Device, MQTT Broker, Software Access Point|
| ESP32  | Guardian |

## Overview
- **/docs**: Contains the Thesis in LaTex format
- **/guardian**: Contains an ESP-IDF project to create an ElectionGuardians
- **/initBallotBox: Contains a Init script that sets up the Ballot Box, an MQTT Broker, a mqtt rule engine (node-red) and a Software Access Point

## Environment Setup
### /initBallotBox
The bash script initBallotBox.sh performs several task in the background. 
- **First Task**: Creates an access point using a program called create_ap. This access point is used in order for the Guardians to communicate with the BallotBox using TCP in a local network.
- **Second Task**: Start an MQTT Broker using mosquitto. The configuration file configures the broker to allow messages within a local network.
- **Third Task**: Start node-red. Node-red is used to trigger activities in the election process.
- **Forth Task**: Run election.py. Election.py runs a mock election and performs crucial election by communicating with the Guardians using mqtt.

/initBallotBox requires the dependencies create_ap, mosquitto, python==3.9 and node-red.

### /guardian
To build the ESP-IDF project for the guardians. ESP-IDF version 5.2 is required.


