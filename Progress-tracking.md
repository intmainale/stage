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
- How should I integrate the shell history command output to the auditd logs?
- How should I parse multiple line commands in autitd logs?

---

## Week 2
🔧 Collector tools setup
- Installed auditd, auditdctl, ausearch: 
    ```sudo apt install auditd audispd-plugins
    sudo systemctl enable auditd
    sudo systemctl start auditd```
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
    -f```
- Bash history configuration -> /etc/bash.bashrc:
    ```export PROMPT_COMMAND='history -a'
    shopt -s histappend```
    