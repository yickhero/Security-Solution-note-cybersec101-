# Security-Solution-note-cybersec101-
Here are my notes after finishing tryhackme Security Solution module
Introduction to SIEM:
SEIM stands for security information and event management system
Two different types of log sources are Host Centric Log Sources(captures events that occurred within or related to the host) and Network-centric log sources(generated when the hosts communicate with each other or access the internet to visit a website)
Devices that generate host centric logs include Windows, Linux, servers. E.g.
1. A user accessing a file
2. A user attempting to authenticate
3. A process execution activity
4. A process adding/editing/deleting a registry key or value
5. PowerShell execution
Devices that generate network-centric logs are firewalls, IDS/IPS, routers, etc E.g.
1. SSH connection
2. A file being accessed via FTP
3. Web traffic
4. A user accessing the company’s resources through VPN
5. Network file sharing Activity
The challenges of using these logs:
1. Too many log sources, they are also scattered across different devices
2. As logs are scattered across different devices we need to connect with each log source through SSH, RDP just to get it
3. Individual logs cannot give out the full context
4. The logs are in different format 
The solution is to use SIEM: 
1. Centrilized log collection
2. Normalization of logs(breaking down a log into several fields for ease of understanding is parsing, and converting all the logs of various log sources into one consistent format is normalization)
3. SIEM correlates the logs of different courses and finds any relationship between them
Windows stores logs in Event Viewer and Linux stores logs in:
/var/log/httpd: Contains HTTP Request  / Response and error logs.
/var/log/cron: Events related to cron jobs are stored in this location.
/var/log/auth.log and /var/log/secure: Stores authentication-related logs.
/var/log/kern: This file stores kernel-related events.
For web servers, It is important to monitor all requests/responses coming in and out of the web server for any potential web attack attempt. In Linux, common locations to write all apache-related logs are /var/log/apache or /var/log/httpd. 
Common methods used by SIEM to investigate logs are:
1. Agent / Forwarder: These SIEM solutions provide a lightweight tool called an agent (forwarder by Splunk) that gets installed on the Endpoint. It is configured to capture and send all the important logs to the SIEM server. 
2. Syslog: Syslog is a widely used protocol to collect data from various systems like web servers, databases, etc., and send real-time data to the centralized destination. 
3. Manual Upload: Some SIEM solutions, like Splunk, ELK, etc., allow users to ingest offline data for quick analysis. Once the data is ingested, it is normalized and made available for analysis 
4. Port-Forwarding: SIEM solutions can also be configured to listen on a certain port, and then the endpoints forward the data to the SIEM instance on the listening port. 
Detection rules for SIEM examples:
If a user gets five failed Login Attempts in 10 seconds, raise an alert for Multiple Failed Login Attempts 
How are the detection rules made:
Adversaries tend to remove the logs during the post-exploitation phase to remove their tracks. A unique Event ID 104 is logged every time a user tries to remove or clear event logs. To create a rule based on this activity, we can set the condition as follows:
Rule: If the Log source is WinEventLog AND EventID is 104 - Trigger an alert Event Log Cleared
Adversaries use commands like whoami after the exploitation/privilege escalation phase. The following Fields will be helpful to include in the rule.
Log source: Identify the log source capturing the event logs
Event ID: Which Event ID is associated with Process Execution activity? In this case, Event ID 4688 will be helpful.
NewProcessName: Which process name will be helpful to include in the rule?
Rule: If Log Source is WinEventLog AND EventCode is 4688, and NewProcessName contains whoami, then Trigger an ALERT WHOAMI command Execution DETECTED
Firewall:
Stateless firewall:
* it operates on layer 3 and layer 4 of the OSI model
* it works solely by filtering the data based on predetermined rules and no previous knowledge
* it can operate quickly
Stateful firewall:
* it keeps track of previous connections and stores them in a state table
* when the firewall denies a packets they deny all the subsequent packets coming from the same source
* also operates on layer 3 and layer 4 of the OSI model
Proxy firewall:
* inspects the traffic coming to an application
*  it act as intermediaries between the private network and the internet and operate on the OSI model’s layer 7
* it inspect the content of all packets
Next-Generation Firewall (NGFW):
* it operates from layer 3 to layer 7 of the OSI model
* it offers deep packet inspection and other functionalities that enhance the security
* it has an intrusion prevention system that blocks malicious activities in real time
* it offers heuristic analysis and analyzing the pattern of attacks and blocking them instantly
* it have SSL/TLS decryption capabilities
Components of a firewall’s rule:
* Source address
* Destination address
* Port
* Protocol
* Action: allow or deny or forward
* Direction
There are inbound rules, outbound rules and forward rules
Netfilter is the framework inside the Linux OS with core firewall functionalities, including packet filtering, NAT, and connection tracking. This framework serves as the foundation for various firewall utilities available in Linux to control network traffic. Some common firewall utilities that utilize this framework are listed below:
iptables: This is the most widely used utility in many Linux distributions. It uses the Netfilter framework that provides various functionalities to control network traffic.
nftables: It is a successor to the “iptables” utility, with enhanced packet filtering and NAT capabilities. It is also based on the Netfilter framework.
firewalld: This utility also operates on the Netfilter framework and has predefined rule sets. It works differently from the others and comes with different pre-built network zone configurations.
ufw (Uncomplicated Firewall), as the name says, eliminates the complications of making rules in a complex syntax in “iptables”(or its successor) by giving you an easier interface
To check status: sudo ufw status
To enable it: sudo ufw enable
To created to allow all the outgoing connections from a Linux machine: sudo ufw default allow outgoing
To deny incoming traffic at any port in your system: sudo ufw deny 22/tcp
To list down all the active rules in a numbered order: sudo ufw status numbered
To delete any rule: sudo ufw delete 2
IDS Fundamentals:
IDS stands for Intrusion Detection System
The IDS plays the role of surveillance cameras. It sits in a corner, monitors the network traffic based on its signature and anomaly-based detections, and detects any abnormal traffic going out or inside the network 
Ways IDS can be deployed:
Host Intrusion Detection System (HIDS): Host-based IDS solutions are installed individually on the hosts and are responsible for only detecting potential security threats associated with that particular host. They provide detailed visibility of the host’s activities. However, host intrusion detection systems can be challenging to manage in large networks as they are resource-intensive and require management on each host. 
Network Intrusion Detection System (NIDS): Network-based IDS solutions are crucial in detecting potentially malicious activities within the whole network, regardless of any specific hosts. They monitor the network traffic of all the hosts involved to detect suspicious activities. It provides a centralized view of all the detections inside the whole network. 
Different detection modes are:
Signature-Based IDS: Many attacks occur every day. Each attack has its unique pattern, which is known as a signature. These signatures are preserved by the IDS in their databases so that if the same attack happens in the future, it gets detected by its signature and reported to the security administrators for action 
Anomaly-Based IDS: This type of IDS first learns the normal behavior (baseline) of the network or system and performs detections if there is any deviation from the normal behavior 
Hybrid IDS: A hybrid IDS combines the detection methods of signature-based IDS and anomaly-based IDS to leverage the strengths of each approach. 
Snort is one of the most widely used open-source IDS solutions developed in 1998. It uses signature-based and anomaly-based detections to identify known threats. There are different mode
Packet sniffer mode: This mode reads and displays network packets without performing any analysis on them 
Packet logging mode: Snort performs detection on the network traffic in real-time and displays the detections as alerts on the console for the security administrators to take action. 
Network Intrusion Detection System mode: Snort’s NIDS mode is the primary mode that monitors network traffic in real-time and applies its rule files to identify any match to the known attack patterns stored as signatures 
Snort rule format:

Action → Protocol → Source IP → Source port → Destination IP → Destination Port → Rule metadata → Message → Signature ID → Rule revision
Rule revision (rev): This sets the rule's revision number. Every time the rule is modified, its revision number is incremented, which helps in tracking changes to any rule 
E.g. alert icmp any any -> 127.0.0.1 any (msg:"Loopback Ping Detected"; sid:10003; rev:1;) 
To start this snort tool: sudo snort -q -l /var/log/snort -i lo -A alert_fast -c /etc/snort/snort.lua
To scan pcap file do: sudo snort -q -l /var/log/snort -r Task.pcap -A alert_fast -c /etc/snort/snort.lua
Vulnerability scanner:
Nessux: It has extensive vulnerability scanning options and is widely used by large enterprises. It is available in both free and paid versions. The free version offers a limited number of scan features. In contrast, its commercial version offers advanced scanning features, unlimited scans, and professional support. Nessus needs to be deployed and managed on-premises. 
Qualys: it provides compliance checks and asset management. It automatically alerts on the vulnerabilities found during continuous monitoring. The best thing about Qualys is that it is a cloud-based platform, which means there is no extra cost or effort to keep it up and running on our physical hardware and manage it. 
Nexpose: It continuously discovers new assets in the network and performs vulnerability scans on them. It gives vulnerability risk scores depending on the asset value and the vulnerability’s impact. It also provides compliance checks against various standards. Nexpose offers both on-premises and hybrid (cloud and on-premises) deployment modes. 
OpenVAS: is an open-source vulnerability assessment solution developed by Greenbone Security. It offers basic features with known vulnerabilities scanned through its database. It is less extensive than commercial tools; however, it gives you the flavor of a complete vulnerability scanner. It is beneficial for small organizations and individual systems 
CVE stands for Common Vulnerabilities and Exposures. Consider CVE a unique number for each of your inquiries and complaints e.g. CVE-2024-9374
It contains CVE-prefix → year → arbitrary digits
CVSS stands for Common Vulnerability Scoring System, it is a score ranging from 0-10 ranking the vulnerability severity, 0-3.9(Low), 4-6.9(Medium), 7-8.9(High), 9-10(Critical)
The installation of OpenVAS can be very hectic as it has many dependencies. We will use docker to install OpenVAS. Docker is a platform that helps you create and distribute packages of different applications e.g. sudo apt install docker.io
After we installed docker on our machine, we can proceed to install OpenVAS within a docker container. For simplicity, we will use the docker image provided by Immauss as it fits everything within a single docker image. E.g.sudo docker run -d -p 443:443 --name openvas immauss/openvas
