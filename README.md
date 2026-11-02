# Security-Solution-note-cybersec101-
Here are my notes after finishing tryhackme Security Solution module
# Security Operations, Firewalls & Vulnerability Scanning Notes

## Security Information and Event Management (SIEM)

A SIEM solution centralizes, normalizes, and correlates logs to detect and alert on malicious activity within an IT environment.

### Log Source Categories

* **Host-Centric Logs:** Captures events occurring on a specific endpoint (Windows, Linux, servers).
* *Examples:* File access, authentication attempts, process execution, registry modifications, PowerShell execution.


* **Network-Centric Logs:** Generated when hosts communicate across a network or access the internet. Captured by firewalls, routers, and IDS/IPS.
* *Examples:* SSH connections, FTP file transfers, web traffic, VPN access, network file sharing.



### The SIEM Solution

Without a SIEM, analysts face scattered logs, varied formatting, and a lack of context. SIEM solves this through:

1. **Centralization:** Aggregating logs from scattered devices into a single dashboard.
2. **Normalization:** Parsing disparate log formats into a single, consistent structure (breaking logs down into standardized fields).
3. **Correlation:** Finding relationships between seemingly isolated events to detect complex attacks.

### Standard Log Locations

* **Windows:** Stored and viewed via the Event Viewer.
* **Linux:**
* `/var/log/auth.log` or `/var/log/secure`: Authentication-related events.
* `/var/log/httpd` or `/var/log/apache2`: Web server HTTP requests, responses, and errors.
* `/var/log/cron`: Cron job execution events.
* `/var/log/kern`: Kernel-level events.



### Log Ingestion Methods

* **Agent / Forwarder:** A lightweight tool installed on the endpoint (e.g., Splunk Universal Forwarder) configured to capture and push logs to the SIEM.
* **Syslog:** A standard protocol used by web servers, databases, and network appliances to stream real-time data to a centralized destination.
* **Port-Forwarding:** The SIEM listens on a specific port, and endpoints are configured to route their log traffic to that port.
* **Manual Upload:** Ingesting offline data (CSV, JSON, log files) for immediate, ad-hoc analysis.

### SIEM Detection Rule Logic

Rules are built by combining specific log fields and event IDs to trigger alerts.

* **Brute Force Rule:** IF `Failed Login Attempts` >= 5 within 10 seconds, THEN trigger "Multiple Failed Login Attempts".
* **Defense Evasion Rule:** IF `Log Source` is WinEventLog AND `EventID` is 104, THEN trigger "Event Log Cleared".
* **Post-Exploitation Rule:** IF `Log Source` is WinEventLog AND `EventCode` is 4688 (Process Execution) AND `NewProcessName` contains "whoami", THEN trigger "WHOAMI Command Execution Detected".

---

## Firewall Architectures

Firewalls filter network traffic based on predetermined rules. A firewall rule dictates traffic based on **Source Address, Destination Address, Port, Protocol, Action (Allow/Deny), and Direction (Inbound/Outbound).**

### Firewall Types

| Firewall Type | OSI Layer | Characteristics |
| --- | --- | --- |
| **Stateless** | Layer 3 & 4 | Filters packets strictly based on predefined rules. Fast, but maintains no memory of previous connections. |
| **Stateful** | Layer 3 & 4 | Tracks active connections in a state table. If a packet is denied, all subsequent packets from that source are automatically blocked. |
| **Proxy** | Layer 7 | Acts as an intermediary between a private network and the internet. Inspects the actual payload/content of the packets. |
| **Next-Gen (NGFW)** | Layer 3 to 7 | Deep packet inspection. Features built-in IPS, heuristic analysis (pattern-based attack blocking), and SSL/TLS decryption. |

### Linux Firewalls (Netfilter)

Netfilter is the core framework inside the Linux kernel handling packet filtering, NAT, and connection tracking. Popular utilities that interface with Netfilter include:

* **iptables:** The legacy, widely used command-line utility.
* **nftables:** The successor to iptables with enhanced filtering and NAT capabilities.
* **firewalld:** Utilizes pre-built network "zones" for easier management.
* **ufw (Uncomplicated Firewall):** A user-friendly frontend that simplifies complex iptables syntax.

**Common UFW Commands:**

* `sudo ufw status` / `sudo ufw status numbered` : Check active rules.
* `sudo ufw enable` : Turn the firewall on.
* `sudo ufw default allow outgoing` : Allow all outbound traffic by default.
* `sudo ufw deny 22/tcp` : Block incoming traffic on port 22 (SSH).
* `sudo ufw delete 2` : Delete rule number 2 from the active list.

---

## Intrusion Detection Systems (IDS)

An IDS acts as a network surveillance camera, monitoring traffic and alerting administrators to anomalous or malicious activity.

### Deployment & Detection Modes

* **HIDS (Host-Based IDS):** Installed on individual endpoints. Provides deep visibility into a specific machine but is resource-intensive to manage at scale.
* **NIDS (Network-Based IDS):** Monitors traffic across the entire network, providing a centralized view of intrusions regardless of the specific host.
* **Signature-Based:** Detects threats by matching traffic against a database of known attack patterns (signatures).
* **Anomaly-Based:** Establishes a baseline of normal network behavior and triggers alerts when traffic deviates from that baseline.
* **Hybrid:** Combines both signature and anomaly detection for comprehensive coverage.

### Snort

Snort is a foundational, open-source IDS. It operates in three main modes:

1. **Packet Sniffer Mode:** Reads and displays live network packets (no analysis).
2. **Packet Logging Mode:** Writes network packets to disk for later analysis.
3. **NIDS Mode:** Monitors real-time traffic and applies rule files to identify attacks.

**Snort Rule Anatomy:**
`[Action] [Protocol] [Source IP] [Source Port] -> [Destination IP] [Destination Port] (Rule Options/Metadata)`

* *Example:* `alert icmp any any -> 127.0.0.1 any (msg:"Loopback Ping Detected"; sid:10003; rev:1;)`
* *sid:* Signature ID (Unique identifier for the rule).
* *rev:* Revision number (increments every time the rule is updated).



**Snort Commands:**

* Start Snort locally: `sudo snort -q -l /var/log/snort -i lo -A alert_fast -c /etc/snort/snort.lua`
* Scan a PCAP file: `sudo snort -q -l /var/log/snort -r Task.pcap -A alert_fast -c /etc/snort/snort.lua`

---

## Vulnerability Scanning

Vulnerability scanners automate the process of discovering network assets and identifying known security flaws.

### Prominent Scanning Solutions

* **Nessus:** Industry standard for large enterprises. Available in free (limited) and paid (unlimited, advanced support) tiers. Managed on-premises.
* **Qualys:** A cloud-based platform requiring no on-premise hardware management. Excels at compliance checks, asset management, and continuous monitoring.
* **Nexpose:** Discovers assets dynamically and assigns vulnerability risk scores based on asset value and potential impact. Supports on-premises and hybrid deployments.
* **OpenVAS:** An open-source assessment solution developed by Greenbone Security. Highly beneficial for small organizations or individual testing.

### Vulnerability Classification

* **CVE (Common Vulnerabilities and Exposures):** A standardized naming convention for publicly known vulnerabilities.
* *Format:* `CVE-[Year]-[Arbitrary Digits]` (e.g., `CVE-2024-9374`).


* **CVSS (Common Vulnerability Scoring System):** A numerical score assessing severity.
* **0.0 - 3.9:** Low
* **4.0 - 6.9:** Medium
* **7.0 - 8.9:** High
* **9.0 - 10.0:** Critical



### OpenVAS Docker Deployment

Because OpenVAS relies on many complex dependencies, deploying it via a Docker container is the most efficient method.

```bash
# Install Docker
sudo apt install docker.io

# Run the unified OpenVAS container (Immauss image)
sudo docker run -d -p 443:443 --name openvas immauss/openvas

```