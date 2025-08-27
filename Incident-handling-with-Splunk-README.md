## Incident Handling With Splunk
<img width="1468" height="1009" alt="Pasted image 20250819014828" src="https://github.com/user-attachments/assets/6de15baa-a1a5-462c-b95d-e7564341ea7f" />


# Summary
Gained hands-on experience in incident handling with Splunk, a SIEM platform that collects and normalizes raw logs.

**TryHackMe Room:** [Incident handling with Splunk](https://tryhackme.com/room/splunk201)

## Tools Used
- Splunk - a SIEM solution that is used for monitoring, searching, and analyzing logs.
## Introduction: Incident Handling
This lab simulates incident handling scenario using Splunk by investigating security events such as system crashes, unauthorized access, and malicious program execution. the goal is to gain hands-on experience leveraging OSINT during investigations, mapping attacker activity to Cyber Kill Chain phases, and performing effective Splunk searches across host- and network-centric logs to triage incidents, correlate events, and hunt for threats.

## Incident Handling - Life Cycle
There are four phases on Incident Response:
- **Preparation** – The organization’s readiness for an incident by having security tools, protocols, and training in place.
- **Detection and Analysis** – Identifying potential security incidents through SIEM/EDR then investigating to determine their scope, impact, and cause.
- **Containment, Eradication, and Recovery** – Stopping the incident to prevent further impact, removing its cause, and restoring affected systems/services back to normal operations.
- **Post-Incident Activity / Lessons Learned** – Reviewing the incident response process after remediation and assessing improvements to prevent future attacks.

## Incident Handling: Scenario

<img width="937" height="395" alt="Pasted image 20250818115452" src="https://github.com/user-attachments/assets/8aef5f84-9304-4f65-a199-78b2bcf23edb" />

After opening Splunk on the attack machine, I ran a query against the **BOTSv1 dataset** (`index=botsv1`) to review logs. From there, I filtered by destination to focus specifically on the domain **imreallynotbatman.com**.

<img width="1919" height="821" alt="Pasted image 20250818133945" src="https://github.com/user-attachments/assets/08dfaa45-7ac0-46ec-8571-b8b12c6d4f5c" />

## Reconnaissance Phase
In the reconnaissance phase, the goal is to collect information about the target and identify potential attack vectors.

From the logs, I identified the attacker’s IP address **40.80.148.42** and the server’s source IP address **192.168.250.70** associated with **imreallynotbatman.com**.”

<img width="1712" height="308" alt="Pasted image 20250818134600" src="https://github.com/user-attachments/assets/d27c2fdf-50cd-4369-9dd7-a565d6a0925d" />

<img width="1708" height="334" alt="Pasted image 20250818134019" src="https://github.com/user-attachments/assets/6f71ea3d-cbc5-45e3-9f98-dfd8763a5774" />

Another way I identified the attacker IP was by running the query `index=botsv1 imreallynotbatman.com sourcetype=stream:http`, which returned all HTTP traffic logs. This allowed me to see if the suspicious domain was contacted through web traffic. This query also also validated that the webserver was running **Joomla** as its CMS

<img width="1919" height="816" alt="Pasted image 20250818164523" src="https://github.com/user-attachments/assets/9ee128ab-957c-48f6-9e38-eabe7ae74ae9" />

<img width="1915" height="607" alt="Pasted image 20250818173010" src="https://github.com/user-attachments/assets/c109e20f-bd04-4d9a-abdb-8725ece68c86" />


Next, I used the query `index=botsv1 imreallynotbatman.com src=40.80.148.42 sourcetype=suricata` to check if Suricata (an IDS/IPS) flagged any activity from this IP. This confirmed that the IP was involved in suspicious traffic. By adding the `alert.signature` field, I was able to see which events were triggered and gain insight into what may have caused the alerts.
<img width="1919" height="761" alt="Pasted image 20250818165939" src="https://github.com/user-attachments/assets/f4db52ef-2e5b-4a8b-aaa9-72dc7dc46c21" />

<img width="903" height="922" alt="Pasted image 20250819075622" src="https://github.com/user-attachments/assets/f94c867e-93de-4f74-b64f-ef913461e61f" />

Next, I modified the query to `index=botsv1 imreallynotbatman.com` and added `sourcetype=suricata "cve"` to check whether any CVEs were associated with the incident. Three appeared in the search suggestions: **CVE-2012-3152**, **CVE-2014-6271**, and **CVE-2015-1635**. After researching each, **CVE-2014-6271 (Shellshock)** seemed the most likely linked to the attack attempt because it directly targets how Bash processes environment variables, allowing attackers to execute malicious commands against vulnerable web servers. The attack matches the attacker's goal of taking over of taking over **[http://www.imreallynotbatman.com](http://www.imreallynotbatman.com)** (Wayne Enterprises).

<img width="1918" height="817" alt="Pasted image 20250818172026" src="https://github.com/user-attachments/assets/41facc7b-23b4-43e6-90d4-c9da77868f27" />

<img width="961" height="977" alt="Pasted image 20250819080545" src="https://github.com/user-attachments/assets/5a4df438-1ab9-4339-88ed-155efd1c554b" />
National Institute of Standards and Technology. _CVE-2014-6271 Detail_. National Vulnerability Database. Published September 24, 2014. Last modified April 12, 2025. Available at: https://nvd.nist.gov/vuln/detail/CVE-2014-6271

Next, I investigated what tool the attacker used for scanning attempts. By examining the **User-Agent** field, I noticed the value `acunetix_wvs_security_test`. Breaking this down, “wvs” refers to **Web Vulnerability Scanner**, and “security test” indicates automated testing activity. Further research confirmed that **Acunetix**, a well-known web application scanner, was the tool used by the attacker to probe the website. 

<img width="1919" height="821" alt="Pasted image 20250818174214" src="https://github.com/user-attachments/assets/9b418c6f-68a4-4303-98b8-4a533ba00a4a" />

<img width="903" height="949" alt="Pasted image 20250819081620" src="https://github.com/user-attachments/assets/fa3014e4-ba9b-4289-a870-1a22034f6aab" />



## Exploitation Phase
In the **exploitation phase**, the objective is to analyze the logs for evidence of how the attacker attempted to exploit vulnerabilities and gain control of the website.

An important query to run is :
```pgsql
index=botsv1 imreallynotbatman.com sourcetype=stream* 
| stats count(src_ip) as Requests by src_ip 
| sort - Requests
```
This query shows the amount of requests from each source IP, and from it I confirmed that the attacker’s IP (40.80.148.42) generated **17,483 requests**, clearly indicating aggressive scanning and exploitation attempts.

<img width="1919" height="534" alt="Pasted image 20250818192219" src="https://github.com/user-attachments/assets/46b7084c-f49b-4690-9dcf-0f12195dbed4" />

Now that I confirmed the website was running Joomla as its CMS, one possible attack vector is brute force. First bruteforcing directories then maybe finding the CMS admin page that the administrator of the website can only access. Joomla has a directory for this, it is **/joomla/administrator/index.php**

<img width="959" height="845" alt="Pasted image 20250818191545" src="https://github.com/user-attachments/assets/9412e888-24ab-4522-ab25-6de081b609ad" />

This prompted me to check for any requests targeting the Joomla admin login directory. I used the queries:
```pgsql
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST uri="/joomla/administrator/index.php" | table _time uri src_ip dest_ip form_data form_data=*username*passwd*
```
and 
```pgsql
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST uri="/joomla/administrator/index.php" | table _time uri src_ip dest_ip form_data
```

These searches allowed me to take a closer look at the activity associated with the brute force attempts. From the results, I was able to confirm that the **username "admin"** was being used during the brute force.

<img width="1919" height="750" alt="Pasted image 20250818193928" src="https://github.com/user-attachments/assets/14a12418-3b33-4812-8f55-b523e52e8289" />

<img width="1919" height="820" alt="Pasted image 20250818194502" src="https://github.com/user-attachments/assets/8bcbea69-d11f-44fb-bcaa-a8e67896cc8c" />


I used the query:
```pgsql
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST form_data=*username*passwd* 
| rex field=form_data "passwd=(?<creds>\w+)" 
| table _time src_ip uri http_user_agent creds 
| stats count by http_user_agent 
| sort - count
```

This helped me extract the attempted credentials and count how many unique passwords were used in the brute force. From the results, I confirmed that **412 unique passwords** were attempted against the Joomla admin login.

<img width="1919" height="368" alt="Pasted image 20250818212031" src="https://github.com/user-attachments/assets/c9005a40-b903-43b4-81b5-328dd8fd7abf" />

Next I used the query:
```pgsql
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST form_data=*username*passwd* 
| rex field=form_data "passwd=(?<creds>\w+)" 
| table _time src_ip uri http_user_agent creds
```
This allowed me to review the captured credentials in detail and pinpoint the log entry where the correct password was used during the brute force attack.

I identified that the brute force password attempts against **imreallynotbatman.com** originated from IP **23.22.63.114**, which suggests the attacker may have been using a VPN. The logs also indicate the brute force tool was built in **Python**. Interestingly, I also saw a single password attempt (**batman**) from IP **40.80.148.42** using the Mozilla browser, which may point to the attacker testing a manual login alongside the automated attack.

<img width="1920" height="820" alt="Pasted image 20250818210828" src="https://github.com/user-attachments/assets/d106a371-5150-451f-a589-de0d7e24a10e" />

## Installation Phase
In the Installation phase, the goal is to investigate host-centric logs to identify what the attacker deployed on the compromised system. This includes detecting any backdoors, web shells, or other malicious files installed to maintain persistence and gain full control of the website.

To do this I searched the query `index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" *.exe` , This filtered HTTP traffic to only requests involving **“.exe”** files. I filtered by the field `part_filename{}`to confirm I was able to confirm that **3791.exe** was delivered to the server. This provided a strong indicator that the attacker uploaded an executable, likely an exploitation script or backdoor.

<img width="1919" height="821" alt="Pasted image 20250818220425" src="https://github.com/user-attachments/assets/c732e417-87d6-4677-a318-3a8e19dc6c22" />


The next step was to determine where the executable ran, since confirming execution helps identify which system was actually compromised. Using this query `index=botsv1 "3791.exe" sourcetype="XmlWinEventLog" EventCode=1` I was able to confirm that 3791.exe was executed on the compromised server. This validated that the uploaded file was not just transferred but actively ran creating a backdoor.
<img width="1919" height="818" alt="Pasted image 20250818222757" src="https://github.com/user-attachments/assets/130c4fbd-cee2-498a-bea3-02cfa350503f" />



After adding MD5 to the query I was able to find the MD5 hash value, **AAE3F5A29935E6ABCC2C2754D12A9AF0** of the process being created. I submit this hash to VirusTotal to examine it further in virus total to get more context of this exploit. This hash can then be submitted to VirusTotal to gain additional context and intelligence on the exploit.
<img width="1919" height="821" alt="Pasted image 20250818222340" src="https://github.com/user-attachments/assets/26d13f46-bc59-4f9b-bb34-b1ea29e05ce4" />


Another important detail returned from this query is the user which is **NT AUTHORITY\IUSR**, a Windows guest user. This indicates the attacker used the webserver to execute the uploaded file.

<img width="900" height="376" alt="Screenshot 2025-08-18 223007" src="https://github.com/user-attachments/assets/c3026f90-3369-4e46-b1fd-bc8102a9396a" />

Searching in VirusTotal came up with the result **`ab.exe`**. According to the [Apache HTTP Server documentation](https://httpd.apache.org/docs/2.4/programs/ab.html), this executable is used for ApacheBench, a tool used to benchmark Apache HTTP servers by sending configurable numbers of HTTP requests to a target server. However, according to [Splunk Security Research](https://research.splunk.com/endpoint/894f48ea-8d85-4dcd-9132-c66cdb407c9b/), attackers can abuse ApacheBench to generate malicious payloads.

<img width="1919" height="821" alt="Pasted image 20250818223936" src="https://github.com/user-attachments/assets/3be06aaa-6b70-4a8a-98f6-fcf2ded532b4" />


## Action on Objectives
Now I investigated what files ended up on the website that led to the defacement. Using the query `index=botsv1 src=192.168.250.70 sourcetype=suricata dest_ip=23.22.63.114`  
I identified two PHP files and one JPEG. The JPEG, **poisonivy-is-coming-for-you-batman.jpeg**, was the file used to deface the _imreallynotbatman.com_ website.

<img width="1919" height="856" alt="Pasted image 20250818233925" src="https://github.com/user-attachments/assets/e903e7b7-1e43-486f-87f8-82a0d5403581" />


Using the query  `index=botsv1 src=40.80.148.42 sourcetype="fortigate_utm" dest_ip=192.168.250.70`  
I was able to review the headers and identify the malicious actions performed by the attacker. The key finding here was the SQL Injection alert (**HTTP.URI.SQL.Injection**), which stands out because it was the initial exploit that triggered the compromise.

<img width="447" height="415" alt="Pasted image 20250818235202" src="https://github.com/user-attachments/assets/f73769e2-5028-47c9-84ab-a8bd1cc50c73" />


## Command and Control Phase
In this phase, I investigated the network-centric logs to identify communication between the compromised server and the adversary’s infrastructure. Using the query:  
`index=botsv1 sourcetype=stream:http dest_ip=23.22.63.114 "poisonivy-is-coming-for-you-batman.jpeg" src_ip=192.168.250.70`  
I found that the results revealed the attacker’s Command & Control (C2) infrastructure, specifically the Fully Qualified Domain Name (FQDN) **prankglassinebracket.jumpingcrab.com**, which the compromised server was communicating with.**

<img width="1919" height="856" alt="Pasted image 20250819001411" src="https://github.com/user-attachments/assets/5d1245a3-7740-4ec0-b999-f5e3e8e01f98" />

## Weaponization Phase
This phase focuses on researching the identified C2 domain to uncover associated domains, subdomains, or IP addresses. This step demonstrates how analysts pivot from domains to IP siblings to uncover additional attacker infrastructure 

Since the provided TryHackMe link ([robtex.com DNS lookup](https://www.robtex.com/dns-lookup/prankglassinebracket.jumpingcrab.com) is not working I will demonstrate using Tryhackme's screenshots. Robtex is a DNS lookup and OSINT tool that allows analysts to pivot from one domain or IP to related infrastructure. By examining prankglassinebracket.jumpingcrab.com on Robtex, I was able to explore the attacker’s broader infrastructure and see how the malicious domain was tied into other resources.

<img width="849" height="768" alt="7ad2296f02b00a73a3ae2e4182fa7cfc" src="https://github.com/user-attachments/assets/dae3a766-0327-4f31-9880-348e60538685" />

In the shared Robtex screenshots, I observed the IP siblings, which are other domains hosted on the same infrastructure as prankglassinebracket.jumpingcrab.com.
<img width="848" height="313" alt="c6aa355d30ed9425cd6e923526a03d46" src="https://github.com/user-attachments/assets/bd64916f-21be-4749-8424-50ca152837bd" />

<img width="447" height="415" alt="Pasted image 20250818235202" src="https://github.com/user-attachments/assets/521e9e14-9707-4646-ad30-b870ea6ca4f9" />


One of these entries showed the attacker’s IP address **23.22.63.114** and its association with the corporate entity mentioned earlier in the scenario.

<img width="859" height="299" alt="2a9dd066e2b6ef2cd55a5e0c04983776" src="https://github.com/user-attachments/assets/d243b70a-cb59-45dc-b3ab-560056e99cc8" />

Pivoting further, I searched the IP in VirusTotal, and under the _Relations_ tab I found the domain **po1s0n1vy.com**, which had a detection linked to malicious activity.

<img width="1919" height="592" alt="Pasted image 20250819005106" src="https://github.com/user-attachments/assets/ef94c563-c2c2-422a-b45d-01f35aff35ec" />

To validate this, I searched both po1s0n1vy.com and the related domain on AlienVault OTX,  a collaboration threat intelligence platform. Reviewing the connected infrastructure, I found additional linked IPs and domains. Tracing through these relationships led me to wanecorpinc.com, which uncovered an email indicator: **LILLIAN.ROSE@PO1S0N1VY.COM**
<img width="1918" height="854" alt="Pasted image 20250819010005" src="https://github.com/user-attachments/assets/4fadd338-6352-4f65-a0e7-63861c3b5264" />

<img width="1919" height="857" alt="Pasted image 20250819010740" src="https://github.com/user-attachments/assets/de1c20b1-c83a-4820-b5e8-5263afe06d2d" />


## Delivery Phase

Since ThreatMiner (used for threat analysis and research) was unavailable, I relied on the TryHackMe screenshots for this step. Searching the IP 23.22.63.114 showed three file hashes. Among them, **c99131e0169171935c5ac32615ed6261** stood out as the only hash associated with detections. This hash corresponds to malware linked to the Poison Ivy APT group, providing another strong indicator of compromise and attribution.

<img width="906" height="625" alt="994b52e66e64ffba61ca57d32ace6a54" src="https://github.com/user-attachments/assets/79408ea2-d619-4224-a46f-40abee8d05be" />


**Hybrid-Analysis** a malware analysis website, was used to examine the malware’s behavior and track its actions after execution. The malware sample tied to the Poison Ivy infrastructure was identified as **MirandaTateScreensaver.scr.exe**.

<img width="912" height="439" alt="6ef05247bb5c92e91d0a2894f219758a" src="https://github.com/user-attachments/assets/98d19e9e-eab8-405f-b7f7-4d85b498ac97" />


## Conclusion
This investigation demonstrates how Splunk can be leveraged for incident handling, starting with the detection of reconnaissance activity and ending with attribution to a known APT group. By following the Cyber Kill Chain phases, I was able to map the attacker's behavior of scanning and brute-forcing Joomla credentials, to the successful installation of malware (`3791.exe` / `ab.exe`), website defacement with the Poison Ivy image, and concluded by C2 communications with malicious infrastructure.

A key takeaway is the importance of pivoting in defensive investigations. Just as attackers pivot between hosts and networks, security analysts pivot across multiple intelligence sources. From domains to IPs, hashes, malware samples, and infrastructure to email addresses. Using tools like VirusTotal, AlienVault OTX, Robtex, and Hybrid-Analysis provided visibility into the attacker’s broader infrastructure, allowed attribution to the Poison Ivy APT group, and reinforced how OSINT works well together with log analysis in Splunk. The lab demonstrated how combining SIEM queries with OSINT tools can give a complete scope of an attack.

### Process Highlights
- **Log Analysis in Splunk**: Queried BOTSv1 dataset for domain, HTTP, IDS, and Windows logs to trace activity.
- **Reconnaissance Detection**: Identified attacker IPs, Joomla CMS detection, and Acunetix user-agent scans.
- **Exploitation Evidence**: Found SQL injection attempts, brute force activity against `joomla/administrator/index.php`, and 412 unique password attempts.
- **Installation Proof**: Confirmed upload and execution of `3791.exe` as `NT AUTHORITY\IUSR`. Also identified hash linked to malicious `ab.exe`.
- **Defacement & Objectives**: Discovered `poisonivy-is-coming-for-you-batman.jpeg` and PHP uploads tied to SQL injection exploitation.
- **C2 Infrastructure**: Mapped communication to `prankglassinebracket.jumpingcrab.com` and related domains.
- **OSINT Pivoting**: Used VirusTotal, AlienVault OTX, Robtex, and Hybrid-Analysis to pivot from IPs to domains, hashes, malware, and email indicators.
- **Attribution**: Correlated findings to Poison Ivy APT group infrastructure, supported by multiple indicators.
