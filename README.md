# IoT Election System
[![ElectionGuard 1.0](https://img.shields.io/badge/🗳%20ElectionGuard-v1.0-green)](https://www.electionguard.vote/spec)

## Overview

This project implements a secure IoT-based election system using ESP32 microcontrollers as guardians and a laptop as the Tallier. The system is based on ElectionGuard 1.0. The system leverages MQTT for communication.

## Devices

| Device   | Role                                                                 |
| -------- | -------------------------------------------------------------------- |
| Laptop   | Tallier, MQTT Broker, Software Access Point, |
| ESP32    | Guardian - Distributed Keygeneration and decryption              |

## Folder Overview

-   **/docs**: Contains the Thesis document and the Guardian Documentation.  Refer to these documents for detailed design information and usage instructions.
-   **/guardian**: Contains the Guardian client code that runs on the ESP32 microcontrollers. This directory holds the source code. The build directory contains the pre-compiled binary that can be flashed onto ESP32 (dual core, 240 MHz, 4 MB flash) devices.
-   **/initBallotBox**: Contains initialization scripts to start the access point, the MQTT broker, and the Tallier on the laptop.
-   **/reference**: Contains the wireshark captures mentioned inside the Thesis.

### /initBallotBox Details

This directory contains scripts to set up the necessary environment on the laptop to act as the central control unit.

-   **initAp.sh**: Enables a software access point (AP) with a specified SSID and password.  This allows the ESP32 guardians to connect to the network.  Requires `create_ap` dependency.  
    *   **Usage:**  `./initAp.sh`
-   **initMQTT.sh**: Starts the MQTT broker (Mosquitto) and configures it to listen for connections from devices connected to the software access point. Requires `mosquitto`.
    *   **Usage:** `./initMQTT.sh`
-   **initBallotBox.sh**: Launches the Tallier, which handles ballot generation, encryption, and communication with the MQTT broker. Requires Python 3.9 or higher.
    *   **Usage:** `./initBallotBox.sh`

## Environment Setup Instructions

Follow these steps to set up the environment and start the election system:

1.  **Install Dependencies:** Ensure that `create_ap`, `mosquitto`, and Python 3.9 (or higher) are installed on the laptop.

2.  **Configure Access Point and MQTT Broker:** Run the `initAp.sh` and `initMQTT.sh` scripts.

3.  **Connect ESP32 Guardians:** Ensure that the ESP32 devices are flashed with the Guardian firmware (see `/guardian` section below). Either build from source or flash with the pre-compiled binary (guardian.bin). It is configured to connect to the SSID set in `initAp.sh`. Optionally, use ESP-IDF monitor to monitor the serial output.

4.  **Start Ballot Box Initialization:** Once both ESP32 devices are connected to the access point, run the `initBallotBox.sh` script in a new terminal window. To reset the ESP32s for subsequent runs press the "EN" button to reset the Guardians.

    ```bash
    cd initBallotBox
    ./initBallotBox.sh
    ```

### /guardian - ESP32 Guardian Firmware

This directory contains the source code and the pre-compiled binary for the ESP32 Guardian firmware.

-   **Requirements:** ESP-IDF version 5.2 is required to build this project.
-   **Building and Flashing:**
    1.  Install ESP-IDF 5.2 following the instructions at [https://docs.espressif.com/projects/esp-idf/en/v5.2/esp32/get-started/index.html](https://docs.espressif.com/projects/esp-idf/en/v5.2/esp32/get-started/index.html).
    2.  Navigate to the `/guardian` directory.
    3.  Configure the project using `idf.py menuconfig`.  **Important:** Set the correct Wi-Fi SSID and password to match the access point created by `initAp.sh`. Also, configure the MQTT Broker address to the IP address of the laptop.
    4.  Build the project using `idf.py build`.
    5.  Flash the firmware to the ESP32 using `idf.py flash monitor`.
