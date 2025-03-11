# ZK-EDI: Zero-Knowledge Edge Data Integrity Verification for Multi-access Edge Computing

## Getting Started

1. Create a MQTT broker. ex:- Mosquitto, HiveMQ, etc.
2. Make sure the edge device is able to run docker images.
3. Clone the repository and navigate into it.
4. Build the Docker image.
    ```bash
    docker build -t <dockerhub_username>/zkedi .
    ```
5. Run the docker image on the edge device with the selected method.
    ```bash
    docker run -e MQTT_USERNAME=<USERNAME> -e MQTT_PASSWORD=<PASSWORD> -e MQTT_URL=<URL> -e MQTT_PORT=<PORT> -e SERVER_ID=<ID> -e METHOD=<METHOD> <dockerhub_username>/zkedi
    ```
6. Run the matching Python notebook for the selected method.
    - ZKEDI: `run_zkedi.ipynb`
    - EDIV: `run_ediv.ipynb`
    - COOPEREDI: `run_cooperedi.ipynb`

### Environment Variables

| Parameter     | Value                          |
|---------------|--------------------------------|
| MQTT_USERNAME | Username for MQTT broker       |
| MQTT_PASSWORD | Password for MQTT broker       |
| MQTT_URL      | URL of MQTT broker             |
| MQTT_PORT     | Port of MQTT broker            |
| SERVER_ID     | Integer value ex:- 0,1,2,3,... |
| METHOD        | `ZKEDI`, `EDIV`, `COOPEREDI`   |
