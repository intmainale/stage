import json


class TopicRouter:
    def route(self, event: str): #event not dict json anymore
        if not event:
            return None, None

        data = json.loads(event)
        measurement = data.get("measurement")

        if measurement == "bash_history":
            return "host/commands/bash", event

        if measurement == "auditd_log":
            return "host/security/auditd", event

        if measurement == "systemd-journald":
            return "host/system/journal", event

        return "host/unknown", event
    
    def parse_line_protocol(self, line):
        measurement_and_tags, _ = line.split(" ", 1)
        parts = measurement_and_tags.split(",")

        measurement = parts[0]
        
        return measurement