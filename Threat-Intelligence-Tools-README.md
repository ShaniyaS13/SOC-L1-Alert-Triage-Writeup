## Threat Intelligence Tools – Practical Lab

<br>

<img width="1490" height="1010" alt="Pasted image 20250817105155" src="https://github.com/user-attachments/assets/96d46e3f-e36b-46c1-8a2e-55c5c6a4eb6d" />

<br>

# Summary
Gain proficiency in using open-source threat intelligence tools to enrich alerts, analyze phishing, and assess indicators of compromise (IOCs).

**TryHackMe Room:** [Threat Intelligence Tools](https://tryhackme.com/room/threatinteltools)

## Tools Used
- **Urlscan.io** – Domain/IP scanning
- **Abuse.ch** – Malware & phishing domain lookup
- **PhishTool** - Email analysis for phishing indicators
- **Cisco Talos** – Threat reputation scoring

## Threat Intelligence
Threat intelligence is the analysis of the tools, methods, and behaviors used by adversaries to identify their patterns. This intelligence helps targeted entities understand potential threats and develop strategies to mitigate risks. There are 4 threat intelligence classifications:

- **Strategic Intel** – High-level intelligence that identifies the organization’s threat landscape and outlines potential risk areas.
- **Technical Intel** – Examines evidence and artifacts from attacks used by an adversary.
- **Tactical Intel** – Uses tactics, techniques, and procedures (TTPs) to assess an adversary’s behavior.
- **Operational Intel** – Identifies the reasoning and intent behind an adversary’s attack.

## UrlScan.io
URLscan.io is a free reconnaissance tool that scans and analyzes websites. It automates the process of gathering activity records and interactions that are associated with a domain. A single scan can reveal:
- Related domains and IPs
- A snapshot of the webpage at the time of the scan
- Technologies in use and site metadata

In this exploring the site I notice that it updates the most recent scans and in another tab it updates live scans. 

<img width="959" height="566" alt="Pasted image 20250815091623" src="https://github.com/user-attachments/assets/aef33e4e-6592-4f59-8567-786152e26d0c" />

<img width="956" height="923" alt="Pasted image 20250815083827" src="https://github.com/user-attachments/assets/72bdfc34-0286-410e-a08c-61c67f298034" />

_Disclaimer: The domains displayed are from public, automatically generated scans on URLscan.io and are used here solely to demonstrate the tool’s interface and functionality. No assumptions are made about the safety or maliciousness of these sites._

### Scan Results
Here is another scan I did on a website which presents all the recon on the specific site. From just this scan I was able to see:
-  Quick information on URL history, site technologies, and page statistics
- All HTTP connections
- links found on the domain
- JavaScript global variables and cookies in the behavior tab
- Indicators listing domains, IPs, and hashes related to the site

<img width="962" height="961" alt="Pasted image 20250815092938" src="https://github.com/user-attachments/assets/8895ef2c-8af0-4134-b6e9-860020d33645" />
<img width="956" height="979" alt="Pasted image 20250815094120" src="https://github.com/user-attachments/assets/950203a0-c9a0-45fe-8f63-a37a2875e458" />
<img width="958" height="884" alt="Pasted image 20250815094147" src="https://github.com/user-attachments/assets/c67321f7-d669-452a-a309-d056a63a5bc7" />
<img width="956" height="979" alt="Pasted image 20250815094247" src="https://github.com/user-attachments/assets/fa416e68-dfa4-4502-b6a2-e076bbf4dc37" />
<img width="958" height="980" alt="Pasted image 20250815094331" src="https://github.com/user-attachments/assets/a57c8a3a-23f4-48c9-8429-5b058879ff10" />

### Example
This is the example Tryhackme gave to explore and identify its details
<img width="1292" height="1004" alt="322ccb4ad9e4a6cd7e2998ba6def47ec" src="https://github.com/user-attachments/assets/3c2ba1a8-7768-465b-bb30-845396a2d056" />
Using a sample domain provided in the lab, I identified:
- It's Cisco Umbrella Rank is **345612**
- Has **13** domains
- Domain registrar is **NAMECHEAP INC**
- The main IP address is **2606:4700:10::ac43:1b0a**

## Abuse.ch
[Abuse.ch](https://abuse.ch) is a website that gather's information on malware and botnets to support threat intelligence efforts. The site hosts six platforms **Malware Bazaar, Feodo Tracker, SSL Blacklist, URL Haus, ThreatFox, Yara IFY.**

As part of the lab, I worked through multiple real-world style IOC lookups using different threat intelligence platforms:

While navigating through **ThreatFox**, I investigated the IOC `212.192.246.30:5555`. The search results showed that this IP and port number is associated with the **Mirai** malware, which is part of the **Katana** malware group. The database entry provided detailed information about this malware helpful for researchers looking to better understand the IOCs. 
<img width="955" height="958" alt="Pasted image 20250815125232" src="https://github.com/user-attachments/assets/c0b444be-284a-4419-a305-c977b8d0b33b" />

<br>
By furthering my curiosity I pressed the provided reference links, I went to MalwareBazaar, where malware samples related to the IOC are available for deeper analysis.

<img width="958" height="977" alt="Pasted image 20250815130037" src="https://github.com/user-attachments/assets/ee816107-a0c3-4e85-a720-22073a2d7005" />

Next, I explored the **SSL Blacklist** platform to investigate the JA3 fingerprint `51c64c77e60f3980eea90869b68c58a8`. The search revealed that this fingerprint is associated with the **Dridex**. 
<img width="958" height="500" alt="Pasted image 20250815134008" src="https://github.com/user-attachments/assets/7fcb2f10-7817-4b6e-a199-cd7e0765aff2" />

<img width="1919" height="982" alt="Pasted image 20250815134216" src="https://github.com/user-attachments/assets/fb21e753-fd31-4144-a6bb-adf7e207fbc2" />

Further into my curiosity, I clicked the link attached to the malware label, and it led me to a new site (not mentioned in the TryHackMe lab) called **Malpedia**. This resource provided an in-depth look at the history of the malware and reference links for further interest.
<img width="932" height="973" alt="Pasted image 20250815134736" src="https://github.com/user-attachments/assets/ff4a3621-5a61-436a-a2ee-722318833018" />

Moving on to **URLHaus**, I searched the ASN number **AS14061** to see what malware-hosting network has it. The results showed **DIGITALOCEAN-ASN** listed in the database, and URLs where the malware was actively being hosted. 
<img width="957" height="978" alt="Pasted image 20250815141553" src="https://github.com/user-attachments/assets/3920cf42-0ab2-4c40-b55c-43e6454966d0" />
<img width="956" height="977" alt="Pasted image 20250815141647" src="https://github.com/user-attachments/assets/aab772d6-5821-48f0-a102-5a27ac07c4f6" />

Last but certainly not least, I went to **FeodoTracker** to check the details of **178.134.47.166**. The results provided information such as its hostname, AS number, origin country (Georgia), and how long it had been active in the network. 
<img width="960" height="976" alt="Pasted image 20250815143503" src="https://github.com/user-attachments/assets/22848518-a25b-4faa-a13f-d281b61496fe" />

## PhishTool
PhishTool is a application that assist security analysts by examining patterns of phishing emails so that they could better identify malicious content in an email. In this lab, I interacted with an attack machine. with a attack machine that will simulate the use of phishtool. In this portion of the lab, I will be interacting with an attack machine that simulates phishing email analysis using PhishTool. 

In this phishing exercise I was able to identify that this was a phishing email. The message was sent to cabbagecare@hotsmail.com, and the email itself appears to be pretending to be from the social media platform LinkedIn. The sender address, **darkabutla@sc500.whpservers.com**, looked suspicious because it was posing as LinkedIn but did not use the company’s official email domain. Instead, it was crafted to mimic a legitimate LinkedIn notification email with the goal of making it trustworthy to the recipient.

<img width="956" height="906" alt="Pasted image 20250816085719" src="https://github.com/user-attachments/assets/5c14bc66-a615-4375-b439-6c8e42d0becd" />

Proceeding with the phishing analysis exercise, I examined the email headers to determine the originating IP address of the suspicious message. By reviewing the “Authentication-Results” section, I identified that the sender IP was **204.93.183.11**. I used **CyberChef** to defang the address, which converted it into the safer format **204[.]93[.]183[.]11**. Defang IP is done to prevent potential harm for clicks and accidental interaction with the IP address.

<img width="548" height="361" alt="Pasted image 20250816094840" src="https://github.com/user-attachments/assets/95496766-9c15-46d3-bbb1-5b9609e7e35e" />

<img width="1919" height="1018" alt="Pasted image 20250816095719" src="https://github.com/user-attachments/assets/050607be-926e-436f-95ae-953863af390a" />


Next, I traced the full path the email took by looking at each “Received” line in the header. These headers revealed the series of mail servers that processed the message before it reached the recipient. By counting the hops, I determined that the email traveled through **four different servers** before being delivered.

<img width="545" height="254" alt="Pasted image 20250816100244" src="https://github.com/user-attachments/assets/02b5d83e-04c2-4a88-a064-59e24ea709e9" />

Through this process I was able to get a better understanding of how phishing analysis is done and how to examine emails more thoroughly. I did this by identifying the suspicious email, viewing it in vim, pulling out the real source of the email, defanging the IP so it’s safe to handle, and checking the email hops to see the path it took.

## Cisco Talos Intelligence
Talos Intelligence is an organized group of security professionals that work together to provide helpful information on actionable intelligence, give visibility on indicators, and offer protection to combat emerging threats.

Using the same IP from the previous exercise, I looked it up on Talos Intelligence to see what would come up. At the time of completing this lab, Talos Intelligence didn’t have the domain listed, so I had to use another method to find it.
<img width="1918" height="980" alt="Pasted image 20250816111230" src="https://github.com/user-attachments/assets/48dc83e0-22ee-47ab-80ad-7efe391716a0" />

I used the **whois** command to search the IP address and was able to obtain both the NetName, **SCNET** (pointed to the domain) and the Customer Name listed as **Complete Web Reviews.**
<img width="248" height="76" alt="Pasted image 20250816122538" src="https://github.com/user-attachments/assets/107bf4b6-5495-4aef-847b-46baada1ba64" />

## Scenario 1
You are a SOC Analyst. Several suspicious emails have been forwarded to you from other coworkers. You must obtain details from each email to triage the incidents reported.   

As instructed I have to examine a phishing email file in the lab to go through with the scenario. I 
see the recipient of the email is chris.lyons@supercarcenterdetroit.com and the sender LeHuong-accounts@gmail.com. I also notice an attachment to this email.

As instructed, I examined the phishing email file provided in the lab. The recipient of the email is chris.lyons@supercarcenterdetroit.com, while the sender is listed as LeHuong-accounts@gmail.com. The email claimed a balance payment was made and refers to a shipper and lists lucy@evvlogistics.com.sg as a contact.

<img width="646" height="891" alt="Pasted image 20250816151144" src="https://github.com/user-attachments/assets/fa32dc10-681e-4afe-b70f-a5db6fcb8f91" />

I take a deeper look into this email and see extension, it has a double extension attached to it .pdf.rar.zip. It gives me a strong indication that the attachment contains malware.

<img width="488" height="395" alt="Pasted image 20250816143002" src="https://github.com/user-attachments/assets/263d8c26-1ecf-4005-a48b-df2cd24d1abb" 

To safely examine and validate what the attachment might contain, I generated a SHA256 hash for the email file using the `sha256sum` command. With that hash, I searched on Talos Intelligence and VirusTotal to see if the sample was already known as malicious. 

<img width="547" height="361" alt="Pasted image 20250816144038" src="https://github.com/user-attachments/assets/4b44831a-fa17-4845-b393-485d07cc1f50" />

<img width="1919" height="980" alt="Pasted image 20250816144215" src="https://github.com/user-attachments/assets/221ca7ee-285b-465f-aada-9c6b0342a9f5" />

<img width="1919" height="980" alt="Pasted image 20250816144525" src="https://github.com/user-attachments/assets/d70e91a9-4fa7-4597-b079-c1684c05aaed" />

When I looked through the results I found that the email had **HIDDENEXT/Worm.Gen** inside of it. After researching, I found it is a worm that hides in real files and then infects once the file is opened.

## Scenario 2
You are a SOC Analyst. Several suspicious emails have been forwarded to you from other coworkers. You must obtain details from each email to triage the incidents reported.

In this next scenario, I examined another phishing email.

<img width="644" height="891" alt="Pasted image 20250816144920" src="https://github.com/user-attachments/assets/cbaf9f04-c2b8-41cd-bc56-7f3624b2452b" />

I noticed the email contains an attachment, **Sales_Receipt 5606.xls**, which is an indicator in phishing attempts since attachments are often used to deliver malware.
<img width="674" height="468" alt="Pasted image 20250816145151" src="https://github.com/user-attachments/assets/ca90de94-b2c5-45fb-bb12-f73cbbd91997" />

<img width="551" height="365" alt="Pasted image 20250816145720" src="https://github.com/user-attachments/assets/fca5aed8-ed47-430c-ad4f-d830705710dc" />

While analyzing it, I noticed a familiar malware that I had come across earlier when I was investigating a JA3 fingerprint. **Dridex** is the malware present in the phishing email.
<img width="1919" height="979" alt="Pasted image 20250816145922" src="https://github.com/user-attachments/assets/9c40932d-ac2b-45b8-a387-e715ff1057b7" />

## Conclusion
Through this lab, I was able to build a stronger understanding of threat intelligence and how analysts use it in practice. I learned how to classify intelligence, research IOCs, and investigate malicious IPs. I also gained experience identifying malware activity through JA3 fingerprints, exploring malware distribution databases, and understanding how researchers track botnet C&C servers. For phishing I practiced using PhishTool to analyze suspicious emails then validate attachments with Talos and VirusTotal. These exercises gave me a realistic process for investigations and showed me the value of curiosity. Digging deeper often revealed resources I wouldn’t have expected to find.
### Process Highlights
- **Research:** Used multiple OSINT tools (Urlscan.io, Abuse.ch, PhishTool, Talos Intelligence, VirusTotal) to investigate IOCs such as IPs, domains, and hashes. Strengthened my ability to validate IOCs across multiple platforms.
- **Malware Identification:** Verified malware (Dridex and Worm.Gen) embedded in phishing emails through Talos and VirusTotal.
- **Phishing Email Analysis**: Improved skills by examining headers, reading email hops, defanging IOCs, and analyzing attachments to identify hidden malware.


















