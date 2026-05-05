class Normalizer:
    def normalize(self, event: dict):
        if not event:
            return None

        return {
            "timestamp": float(event.get("timestamp", 0)), #do i need it?
            "source": event.get("source", ""),
            "event_type": event.get("event_type", ""),
            "message": (event.get("message") or "").strip(),
            "command": (event.get("data", {}) or {}).get("command", "")
        }