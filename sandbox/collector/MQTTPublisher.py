# later you'll plug paho-mqtt

class MQTTPublisher:
    def __init__(self, logger):
        self.logger = logger

    def publish(self, topic, payload):
        self.logger.debug(f"Publishing to {topic}: {payload}")
        # mqtt_client.publish(topic, json.dumps(payload))