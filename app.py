from edge_server_factory import EdgeServerFactory
import dotenv
import os
import paho.mqtt.client as mqtt

# Load the environment variables
dotenv.load_dotenv()

# Get an instance of the given EDI verification method
edge_server = EdgeServerFactory.get_edge_server(os.getenv("METHOD").upper())

# Callback for when the client receives a CONNACK response from the server
def on_connect(client, userdata, flags, reason_code, properties=None):
    if reason_code == 0:
        print(f'{edge_server.get_current_time()} Connected with result code: {reason_code}')
        client.subscribe(os.getenv("METHOD").upper(), qos=1)
        client.subscribe(f'SERVER{os.getenv("SERVER_ID")}', qos=1)


# Callback for when the client receives a SUBACK response from the server
def on_subscribe(client, userdata, mid, granted_qos, properties=None):
    print(f'{edge_server.get_current_time()} Subscribed to topic with QoS {granted_qos}')


# Callback for when a message is received
def on_message(client, userdata, msg):
    # print(f'{edge_server.get_current_time()} Received message on topic "{msg.topic}": {msg.payload.decode("latin-1")}')
    edge_server.process_message(client, msg.payload.decode("latin-1"))


# Create an MQTT client instance
client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
# client.tls_set(tls_version=mqtt.ssl.PROTOCOL_TLS)
client.username_pw_set(os.getenv('MQTT_USERNAME'), os.getenv('MQTT_PASSWORD'))

# Set the callbacks
client.on_connect = on_connect
client.on_subscribe = on_subscribe
client.on_message = on_message

# Connect to the broker
client.connect(os.getenv('MQTT_URL'), int(os.getenv('MQTT_PORT')))

# Start the loop to listen for messages
client.loop_forever()
