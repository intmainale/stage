# NullHive Honeypot

## Description

NullHive is a modular honeypot log collection framework built with a hexagonal architecture. It combines collectors, parsers, enrichers, and publishers into a configurable event-processing pipeline.

The framework is designed for vulnerable hosts and research environments where collecting attacker behavior, shell activity, audit events, and web traffic might be required.

---

# Features

- Real-time Bash command collection
- `auditd` `execve` monitoring
- Apache access/error log parsing
- Threat-intelligence enrichment
- MQTT publishing support
- Modular adapter-based architecture
- Persistent logging across reboots
- Automatic Bash history discovery
- YAML-driven configuration

---

# Use Cases

- Collect Bash commands from all users on a compromised host
- Monitor command execution using `auditd`
- Detect suspicious Apache requests
- Enrich attacker IPs using:
  - VirusTotal
  - AbuseIPDB
  - Shodan
- Forward normalized events into:
  - MQTT/TIG stack
  - SIEM pipelines
  - Debug log files

---

# Requirements

- Linux host
- Python 3.10+
- Root privileges
- Installed services matching enabled collectors

Python dependencies:

- `PyYAML`
- `paho-mqtt`

Install:

```bash
pip install -r requirements.txt
```

---

# Recommended Installation

The recommended installation method is using the automated setup script.

## Quick Start

Run:

```bash
sudo bash install.sh
```

The installer can:

- Configure persistent Bash history collection
- Configure `auditd`
- Create required directories
- Install dependencies
- Generate example configs
- Enable system-wide logging
- Validate service paths

---

# Manual Installation

## 1. Create Virtual Environment

```bash
python -m venv .venv
source .venv/bin/activate
```

## 2. Install Dependencies

```bash
pip install -r requirements.txt
```

## 3. Run NullHive

```bash
sudo python main.py
```

---

# Configuration

Configuration lives in:

```text
honeypot-system/config/settings.yaml
```

---

# Pipeline Configuration

Example:

```yaml
pipeline:
  services:   ["bash", "apache", "auditd"]
  collectors: ["bash", "apache", "auditd"]
  publishers: ["mqtt"]
  enrichers:  ["virustotal", "abuseipdb", "shodan"]
```

---

# Bash History Collection

NullHive supports real-time Bash command collection for all users.

The recommended approach is to centralize all Bash histories into:

```text
/var/log/bash-history/
```

This survives reboots and allows the collector to monitor all users consistently.

---

## Automatic Setup (Recommended)

Run:

```bash
sudo bash install.sh
```

and select:

```text
[1] Configure Persistent Bash Logging
```

The installer automatically:

- Creates `/var/log/bash-history`
- Enables timestamps
- Enables immediate command flushing
- Configures all interactive shells
- Makes logging persistent across reboots

---

## Manual Bash Configuration

Create:

```bash
sudo nano /etc/profile.d/nullhive-history.sh
```

Add:

```bash
# Enable timestamps
export HISTTIMEFORMAT="%F %T "

# Append instead of overwrite
shopt -s histappend

# Centralized history location
export HISTFILE="/var/log/bash-history/$(id -un).history"

# Flush history immediately
export PROMPT_COMMAND='history -a'
```

---

## Create the Logging Directory

```bash
sudo mkdir -p /var/log/bash-history
sudo chmod 1777 /var/log/bash-history
```

The sticky bit (`1777`) prevents users from deleting each other's history files.

Each user automatically gets an individual history file:

```text
/var/log/bash-history/root.history
/var/log/bash-history/alice.history
/var/log/bash-history/bob.history
```

NullHive recommends using:

```bash
$(id -un)
```

instead of `${USER}` because it resolves the real system username and is harder to spoof in a honeypot/auditing environment.

---

## Configure Log Rotation

Create:

```bash
sudo nano /etc/logrotate.d/nullhive-bash
```

Add:

```conf
/var/log/bash-history/*.history {
    daily
    rotate 30
    compress
    missingok
    notifempty
    copytruncate
}
```

This configuration:

- rotates logs daily
- keeps 30 compressed archives
- prevents unbounded file growth
- avoids requiring shell restarts

Because log rotation manages retention, `HISTSIZE` and `HISTFILESIZE` are intentionally omitted from the configuration.

---

## Ensure Non-Login Shell Support

Append to:

```text
/etc/bash.bashrc
```

```bash
source /etc/profile.d/nullhive-history.sh
```

---

## Reload Configuration

```bash
source /etc/profile.d/nullhive-history.sh
```

or reconnect via SSH.
---

### Example Output

```text
2026-05-21 14:12:11 ls -la
2026-05-21 14:12:15 whoami
2026-05-21 14:12:20 sudo systemctl status ssh
```

---

# Important Notes About Bash History

Bash history collection is useful for:

- Honeypots
- Research
- Telemetry

However, it is **not tamper-proof**.

Attackers can bypass it using:

```bash
unset HISTFILE
history -c
export PROMPT_COMMAND=""
```

or alternative shells/tools.

For reliable auditing, use `auditd` together with Bash history.

NullHive is designed to combine both sources.

---

# `auditd` Configuration

NullHive works by monitoring only `execve` events to reduce noise.

Create:

```text
/etc/audit/rules.d/nullhive.rules
```

Add:

```bash
-a exit,always -F arch=b64 -S execve -k execve
-a exit,always -F arch=b32 -S execve -k execve
```

Reload:

```bash
sudo augenrules --load
sudo systemctl restart auditd
```

---

# Collector Paths

Example:

```yaml
collectors:

  bash:
    path: "/var/log/bash-history"

  auditd:
    path: "/var/log/audit/audit.log"

  apache:
    path:
      - "/var/log/apache2/access.log"
      - "/var/log/apache2/error.log"
```

---

# Auto-Discovery

NullHive automatically scans:

```text
/home/*/.bash_history
```

when explicit paths are not configured.

If centralized logging is enabled, this step is unnecessary.

---

# Publishers

Supported publishers:

- `mqtt`
- `debug`

Example:

```yaml
publishers:
  mqtt:
    host: "localhost"
    port: 1883
```

MQTT topics are generated as:

```text
eurosystem/<source>/<host>
```

---

# Enrichers

Supported enrichers:

- `virustotal`
- `abuseipdb`
- `shodan`

Example:

```yaml
enrichers:
  virustotal:
    api_key: ""

  abuseipdb:
    api_key: ""

  shodan:
    api_key: ""
```

---

# IP Extraction Requirement

Enrichment only works if parsers extract valid IP addresses from events.

For example:

- Apache logs → client IP
- SSH logs → remote IP
- Audit logs → optional IP if correlated

---

# Project Architecture

NullHive follows a hexagonal architecture:

```text
Collectors → Parsers → Enrichers → Publishers
```

New adapters can be added independently with minimal modification.

---

# Adding a New Collector

1. Add the collector name to:

```yaml
pipeline:
  collectors:
  services:
```

2. Add collector configuration under:

```text
config/settings.yaml
```

3. Implement the adapter

4. Register it in:

```text
src/factories/concrete_factories.py
```

---

# Security Disclaimer

NullHive is intended for:

- Honeypots
- Malware research
- Detection engineering
- Threat research

Do NOT deploy on production systems without understanding the privacy and legal implications of command collection and auditing.