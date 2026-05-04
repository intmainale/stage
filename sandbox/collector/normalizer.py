class Normalizer:
    def normalize(self, event: dict):
        if not event:
            return None

        event["timestamp"] = str(event["timestamp"])
        event["message"] = event["message"].strip()

        return event