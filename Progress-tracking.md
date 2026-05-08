# Progress Tracking – Honeypot Project

This document tracks weekly progress, decisions, and technical evolution of the honeypot system.

---

## Legend
- 🧠 Learning / Research
- ⚙️ Implementation
- 🔧 Configuration / Fixes
- 🧪 Testing / Validation
- 📦 Deployment
- 🧾 Documentation
- 📖 References

---

## Week 1
🧠 Learning about VM infrastructure and deep dive into SSH protocol
- Studied how virtual machines isolate network environments (TODO)  
- Dive into NAT vs bridged networking  (TODO)
- Reviewed SSH authentication methods (password vs key-based auth vs CA-based auth)  
- Investigated SSH most common CVEs  (TODO)
🧠 Research on honeypot concepts and threat modeling  
- Explored what honeypots are used for in cybersecurity monitoring
- Viewed some modules of well-known honeypots such as Cowrie
- Compared low-interaction vs high-interaction honeypots (TODO)
- Evaluated Cowrie as SSH/Telnet emulation tool  (TODO)
- Defined initial goal: log attacker behavior without system compromise
🧠 Learning about linux logging systems
- Learned about rsyslog, journald, auditd
- Discovered the logging concurrency problem on a multi-session enviroment

🔧 VM setup and network configuration
- Created VM instance (provider: Hetzner)  
- Configured firewall rules (initial allow/deny policies) both network side and client side
- Set up SSH access with key authentication for safe access to the vulnerable VM
- Changed default SSH port for security baseline
- Changed root psw, added an admin client as decoy (admin:admin) and a real admin to perform operations

🧪 Testing remote access to the VM setup
- SSH service is enabled and online
- SSH access is configured correctly for all users

⚙️ Development enviroment setup
- Installed python, pip and venv
- Created the repo to pull from the vulrnerable VM

🧾 First draft of requirements analysis
- High level view of the system, glossary setup
- Identify functional and non-functional requirements
- Identify system costraints and actors
- Draft first use cases: UC1, UC1.1, UC1.2, UC1.3, UC2, UC3, UC3.1, UC3.2

📖 

### Open Questions
- How should a log collector behave in an enviroment that requires parallelization?
- How should I integrate the shell history command output to the auditd logs? (Week 2: optional)
- How should I parse multiple line commands in autitd logs?

---

## Week 2
🧠 Delving into MQTT protocol and alternatives
- Learned about MQTT protocol and its use cases
- Explored MQTT alternatives: Apache Kafka, HTTP REST

🧠 Learning about TIG pipeline and alternatives
- Learned about Telegraf use cases and integration with MQTT and InfluxDB
- Studied how InfluxDB works in high throughput enviroments without losing performance
- Researched about the integration between Grafana and InfluxDB
- Learned about Grafana capabilites
- Evaluated the ELK stack integration but it didn't meet the requirements for this project

🧠 Researching about Docker routing feature
- Studied a way to make my docker containers communicate between VMs
- Looked for a way to manage firewalls and docker ports

🧠 Researching for log patterns
- Delved into auditd, journald logs
- Searched for valid parameters to keep track of

🧠 Studying Telegraf gjson path sintax to setup its json_v2 parser
- Learned about gjson sintax
- Looked for a way to tune the json into a good influxDB output

🔧 Collector tools setup
- Installed auditd, auditdctl, ausearch: 
    ```sudo apt install auditd audispd-plugins
    sudo systemctl enable auditd
    sudo systemctl start auditd
- Enabled execution tracking, reboot persistent -> /etc/audit/rules.d:
    ```## First rule - delete all
    -D
    ## Execution tracking
    -a always,exit -F arch=b64 -S execve -k shell_cmds
    ## Increase the buffers to survive stress events.
    ## Make this bigger for busy systems
    -b 8192

    ## This determine how long to wait in burst of events
    --backlog_wait_time 60000

    ## Set failure mode to syslog
    -f
- Bash history configuration -> /etc/bash.bashrc:
    ```export PROMPT_COMMAND='history -a'
    shopt -s histappend

🔧 Telegraf and MQTT broker setup
- Installed mosquitto: https://mosquitto.org/download/
- Telegraf setup: 
    ```docker pull telegraf

-- Create folder C:\telegraf and file telegraf.conf:
    ```[agent]
    interval = "5s"

    [[inputs.mqtt_consumer]]
    servers = ["tcp://host.docker.internal:1883"]

    topics = ["host/#"]

    qos = 1
    data_format = "json"

    [[outputs.file]]
    files = ["stdout"]

    ```docker run -d --name telegraf -v C:\telegraf\telegraf.conf:/etc/telegraf/telegraf.conf:ro telegraf
- Telegraf setup change:
    ```[agent]
    interval = "500ms"
    flush_interval = "1s"

    metric_batch_size = 5000
    metric_buffer_limit = 50000

    collection_jitter = "1s"
    flush_jitter = "2s"

    # =========================
    # INPUT: MQTT consumer
    # =========================
    [[inputs.mqtt_consumer]]
    servers = ["tcp://mosquitto:1883"]

    topics = [
        "host/#"
    ]

    qos = 1

    connection_timeout = "30s"

    data_format = "influx"

    # =========================
    # OUTPUT: InfluxDB v2
    # =========================
    [[outputs.influxdb_v2]]
    urls = ["http://influxdb:8086"]

    token = "${INFLUX_TOKEN}"
    organization = "${INFLUX_ORG}"
    bucket = "${INFLUX_BUCKET}"

    timeout = "10s"

    # =========================
    # OUTPUT: File (for debugging)
    # =========================
    [[outputs.file]]
    files = ["stdout"]
    data_format = "influx"

🔧 InfluxDB and Grafana setup
- Created an account on both services
- InfluxDB organization, bucket setup

⚙️ PoC
- Creation of a python collector with multithreading: pipeline that collect events from 3 sources real-time, normalizes the raw data and routes the output to a specific topic, ready to be published
- Logging system as a debug tool
- MQTT python client setup
- Telegraf .conf file setup for InfluxDB and mosquitto services integration
- Grafana integration with InfluxDB
- Organized a docker enviroment with 2 containers:
    1. collector
    2. mosquitto, telegraf, influxdb and grafana
- Collector structure: 
-- **baseCollector** abstract class that defines the basic methods of the collector classes
-- **auditdCollector**, **bashHistoryCollector**, **journalCollector** are the implementation of the previous class, which identify the services
-- **logger** is an utility class used for production debug purposes
-- **normalizer** is a parser that make the input ready to be published via MQTT
-- **topicRouter** sorts the parsed logs per MQTT topic
-- **MQTTPublisher** manages the connection to the MQTT broker and the data publishing in the right topic
-- **threadCollector** is a class that implements multithreading: 1 thread per event
-- **orchestrator** creates the collector pipeline, from the logs collection to their publishing

🧾 Choosing the technologies
- MQTT over Apache Kafka and HTTP REST
- Python as programming language
- TIG pipeline over ELK pipeline
- Docker for deployment

📖 MQTT, Apache Kafka, Telegraf, Docker networking, InfluxDB OSS v2
- MQTT doc: https://docs.oasis-open.org/mqtt/mqtt/v5.0/mqtt-v5.0.html
- mosquitto: https://mosquitto.org/documentation/
- Apache Kafka use cases: https://kafka.apache.org/42/getting-started/uses/
- Telegraf: https://docs.influxdata.com/telegraf/v1/
- Docker networking: https://docs.docker.com/engine/network/
- Docker port publishing: https://docs.docker.com/engine/network/port-publishing/
- InfluxDB OSS v2: https://docs.influxdata.com/influxdb/v2/
- InfluxDB errors: https://docs.influxdata.com/influxdb/v1/troubleshooting/errors/
- Telegraf? input data format json_v2: https://docs.influxdata.com/telegraf/v1/data_formats/input/json_v2/, https://www.influxdata.com/blog/how-parse-json-telegraf-influxdb-cloud/, https://www.influxdata.com/blog/mqtt-topic-payload-parsing-telegraf/
- Auditd log structure: https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/security_guide/sec-understanding_audit_log_files, https://access.redhat.com/articles/4409591#audit-record-types-2, https://access.redhat.com/articles/4409591#audit-event-fields-1
- InfluxDB gjson path syntax: https://github.com/tidwall/gjson/blob/v1.7.5/SYNTAX.md
- Agent, tagdrop, input plugin configuration telegraf: https://docs.influxdata.com/telegraf/v1/configuration/#create-a-configuration-with-default-input-and-output-plugins
- Store secrets telegraf: https://docs.influxdata.com/telegraf/v1/configuration/#secret-store-secrets
