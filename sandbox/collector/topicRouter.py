class TopicRouter:
    def route(self, event: dict):
        if not event:
            return None, None

        source = event.get("source")

        if source == "bash":
            return "host/commands/bash", event

        if source == "auditd":
            return "host/security/auditd", event

        if source == "journalctl":
            return "host/system/journal", event

        return "host/unknown", event