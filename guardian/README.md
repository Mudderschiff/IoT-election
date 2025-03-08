# Guardian - ElectionGuard ESP32 Client

## Overview

This project provides the source code and configuration necessary to build an ElectionGuard guardian client for the ESP32 platform. The guardian client is responsible for securely participating in the key generation ceremony and the tallying phase from the the ElectionGuard 1.0. This client communicates via MQTT to a central broker (Laptop).

## Project Structure

The project is organized into the following directories and files:

*   **`main/`**: Contains the main application entry point and performance testing code.
    *   `main.c`: The main application logic that initializes the MQTT client and handles communication with the central server.
    *   `test_performance.c`:  A performance testing module used to evaluate the efficiency of cryptographic operations used during the ElectionGuard key generation ceremony.

*   **`/components`**: Contains reusable modules that encapsulate specific functionalities.
    *   **`/wolfssl`**:  This component overrides the default settings of the WolfSSL third-party library. 
 
    *   **`/adapter`**:  Handles all communication aspects of the guardian client.
        *   Sets up an MQTT client using the configured Wi-Fi connection.
        *   Manages incoming and outgoing MQTT messages.
        *   Serializes and deserializes data for transmission.
    *   **`/model`**:  Contains the core business logic and cryptographic operations required by the ElectionGuard protocol.
        *   Implements the key ceremony and the distributed decryption
        *   Provides an abstraction layer for the underlying cryptographic primitives.

## Functionality

The `main.c` file initializes the ESP32, connects to the configured Wi-Fi network, and starts the MQTT client using the `adapter` component. The `adapter` component then handles communication with the central server, receiving instructions and sending responses. The `model` component implements the cryptographic logic required to perform the ElectionGuard operations.

The `test_performance.c` file provides a means to benchmark the performance of the cryptographic operations used in the `model` component. This is crucial for ensuring that the guardian client can perform its tasks within a reasonable timeframe on the resource-constrained ESP32 platform.

## Building and Flashing

This project is designed to be built using the ESP-IDF framework.

1.  **Install ESP-IDF version 5.2:**
2.  **Clone the Repository:** Clone this repository to your local machine.
3.  **Configure the Project:**
    *   Navigate to the project directory in your terminal.
    *   Run `idf.py menuconfig` to open the ESP-IDF configuration menu.
    *   **Wi-Fi Configuration:**  Configure the Wi-Fi SSID and password to connect to your Access Point.  This is essential for the guardian to communicate with the MQTT broker.
    *   **MQTT Broker Configuration:**  Set the MQTT broker address (IP address or hostname) and port.  This should match the configuration of the MQTT broker running on the central server.
    *   **Other Settings:**  Configure any other project-specific settings as needed.
4.  **Build the Project:** Run `idf.py build` to compile the project.
5.  **Flash the Firmware:** Run `idf.py flash monitor` to flash the firmware to your ESP32 and monitor the serial output.

## Testing and Performance Evaluation

To evaluate the performance of the cryptographic operations, you can use the `test_performance.c` module.

1.  **Enable Performance Testing:**  Modify `main.c` to call the functions in `test_performance.c`.  You need to comment out the MQTT client initialization code to isolate the performance tests.
2.  **Build and Flash:**  Build and flash the firmware as described above.
3.  **Monitor Serial Output:**  The serial output will display the results of the performance tests, including the execution time for various cryptographic operations.
