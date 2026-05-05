import json
import time
import threading
import paho.mqtt.client as mqtt
import os

class MQTTPublisher:
    def __init__(
        self,
        logger,
        host="172.24.151.21", #os.getenv("MQTT_HOST", "localhost"),
        port=1883,
        client_id="log-publisher",
        username=None,
        password=None,
        keepalive=60
    ):
        self.logger = logger
        self.host = host
        self.port = port
        self.keepalive = keepalive

        self.client = mqtt.Client(client_id=client_id)

        if username and password:
            self.client.username_pw_set(username, password)

        # callbacks
        self.client.on_connect = self.on_connect
        self.client.on_disconnect = self.on_disconnect

        self.connected = False
        self._lock = threading.Lock()

        self._connect()

    # -----------------------
    # Connection management
    # -----------------------
    def _connect(self):
        try:
            self.logger.info(f"Connecting to MQTT {self.host}:{self.port}")
            self.client.connect(self.host, self.port, self.keepalive)

            # start network loop in background thread
            self.client.loop_start()

        except Exception as e:
            self.logger.error(f"MQTT connection failed: {e}")

    def on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            self.connected = True
            self.logger.info("MQTT connected")
        else:
            self.logger.error(f"MQTT connection failed with code {rc}")

    def on_disconnect(self, client, userdata, rc):
        self.connected = False
        self.logger.error("MQTT disconnected")

        # auto-reconnect loop
        while not self.connected:
            try:
                self.logger.info("Reconnecting to MQTT...")
                client.reconnect()
                time.sleep(2)
            except Exception as e:
                self.logger.error(f"Reconnect failed: {e}")
                time.sleep(5)

    # -----------------------
    # Publish
    # -----------------------
    def publish(self, topic, payload):
        if not topic or not payload:
            return

        try:
            message = json.dumps(payload)

            if not self.connected:
                self.logger.debug("MQTT not connected, dropping message")
                return

            with self._lock:
                result = self.client.publish(topic, message, qos=1)

            if result.rc != mqtt.MQTT_ERR_SUCCESS:
                self.logger.error(f"Publish failed: {result.rc}")

            else:
                self.logger.debug(f"Published to {topic}")

        except Exception as e:
            self.logger.error(f"Publish error: {e}")

    # -----------------------
    # Shutdown
    # -----------------------
    def stop(self):
        self.logger.info("Stopping MQTT publisher")
        self.client.loop_stop()
        self.client.disconnect()