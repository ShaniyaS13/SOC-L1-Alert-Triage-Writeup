# SOC L1 Alert Triage – Practical SOC Training
<img width="1457" height="980" alt="Pasted image 20250813000640" src="https://github.com/user-attachments/assets/597ebd91-4ad2-45f2-a716-751261631dae" />

# Summary
Simulated Tier 1 SOC Analyst workflow in a hands-on lab environment performing alert triage, determining severity, documentation, and escalating incidents within a simulated SIEM platform.

**TryHackMe Room:** [SOC L1 Alert Triage](https://tryhackme.com/room/socl1alerttriage)

## Tools Used
**SIEM (Security Information and Event Management)** – for log review, filtering, and alert analysis.

## Skills Demonstrated
- Understanding what an alert is and how to monitor it effectively.
- Familiarized myself with a SIEM dashboard by interacting with it and applying filters.
- Analyzing alerts and classifying them based on severity and type.
- Tracking alert status through different stages of investigation.
- Identifying which alerts should be remediated first based on priority.
- Efficiently assessed alerts to ensure they are addressed in the correct order and manner.
- Following a defined workflow for the escalation process.
## Task 1: Introduction
This introductory module explains what an alert is and why it plays a critical role for SOC teams. It provides a foundation for making informed decisions on how a SOC analyst should respond to an alert and manage it effectively. For this task I am given access to a simulated SOC dashboard in TryHackMe SIEM. Here is the SOC Dashboard provided:

<img width="540" height="316" alt="Pasted image 20250812183853" src="https://github.com/user-attachments/assets/67308704-2b08-4301-b71c-786717d712a9" />
<img width="1193" height="519" alt="Pasted image 20250812184100" src="https://github.com/user-attachments/assets/e2fa28c6-12e7-41b9-b305-8865caaef882" />

## Task 2: Events and Alerts
It is crucial for a SOC analyst to recognize alerts, understand how they are generated, and know how to respond to them. On a day-to-day basis, SOC analysts encounter many alerts triggered by suspicious events, and having a security solution in place such as a SIEM or EDR helps manage alerts by processing logs so they can be triaged. SOC L1 analysts are the first to receive these alerts, and they are tasked with determining which ones are critical. The critical alerts are then escalated to the SOC L2 team for deeper investigation.

When I accessed the SOC dashboard I identified 5 alerts and the most recent one is **"Double-Extension File Creation"**, a type of alert that indicates a potential file obfuscation technique, where the attacker adds another extension to a file to bypass restrictions.

<img width="1145" height="505" alt="Pasted image 20250812205645" src="https://github.com/user-attachments/assets/67914f86-4da1-460d-88b9-387f58037c21" />
<img width="1103" height="275" alt="Pasted image 20250814110528" src="https://github.com/user-attachments/assets/ea357fcd-f0ae-45e1-8922-158c6a2eece0" />

## Task 3: Alert Properties
Alert properties describe the details and attributes of an alert, helping analysts classify what it is and assess its significance. For example, the alert **"Unusual VPN Login Location"** was classified as a **false positive**. Further analysis of the related log reveals the user who triggered it. 

When reviewing the alert in the SIEM, I was able to view the additional information gathered in the log:
- Description that explains the event that triggered the alert.
- Source IP which is the network address from which the event originated.
- Source user that is identified as **M.Clark**.
- Login country which shows the location where the login occurred.
- Expected country for the location expected for this user’s activity.
- Comment added by another SOC Analyst, providing context from their review of the alert.

The comment noted that M.Clark is a corporate CEO and confirmed that they accessed the VPN while they are on vacation. To inform the SOC team that this alert was a false positive and needs no escalation.

<img width="1134" height="485" alt="Pasted image 20250812204508" src="https://github.com/user-attachments/assets/9f433842-913a-41f5-bb91-625b03040d07" />
<img width="1103" height="261" alt="Pasted image 20250812205033" src="https://github.com/user-attachments/assets/c44e9a69-6c3e-4486-b1e1-ea4e27a77baa" />

## Task 4: Alert Prioritization
Alert prioritization is the process of deciding which alerts to investigate first. This is done by checking the alert hasn’t already been reviewed, checking its severity level, and considering when it occurred. Always prioritize the most critical alerts first, as they are more likely to represent severe threats. Older alerts should be handled before newer ones, since the attacker may already be in a later stage of their attack compared to a threat that just triggered a new alert.

<img width="1156" height="515" alt="Pasted image 20250812222043" src="https://github.com/user-attachments/assets/4e19fc82-f2a5-468f-a37e-38b364fc2faf" />

Based on the alerts displayed, the critical alert **"Potential Data Exfiltration"** is the best to address first. I assigned it to myself and changed the status to **"In Progress"** to inform the SOC team that I am working to remediate this threat.

<img width="1220" height="669" alt="Pasted image 20250812222358" src="https://github.com/user-attachments/assets/11652c53-ed81-44b2-b835-331287565d86" />

<img width="1104" height="47" alt="Pasted image 20250812222430" src="https://github.com/user-attachments/assets/2b8d3dff-5a1c-42c5-9f32-86d53d39203b" />

## Task 5: Alert Triage
Alert triage involves the prioritization and assessment of a specific alert, starting with taking ownership of the alerts assigned to you. Then, investigate the alert while referencing a playbook or runbook. Lastly, once the alert is assigned a verdict, it is either escalated or closed. This ensures the alert is handled efficiently and gives the SOC analysts the opportunity to review it in detail.

1. I began by examining the most critical alert, **"Potential Data Exfiltration"**. Reviewing the log data revealed traffic was coming from zoom.us application and the source network involved a meeting room. This indicated that the activity likely came from users on the network participating in a video conference call. Given the context, I determined this to be a **false positive**, added a comment explaining the reasoning, and closed the alert.
   <img width="908" height="250" alt="Pasted image 20250814135218" src="https://github.com/user-attachments/assets/2801b4e7-07be-4624-b33c-5110abca0869" />
   <img width="501" height="343" alt="Pasted image 20250814135928" src="https://github.com/user-attachments/assets/68229ac4-6169-48b0-963a-679ec656d086" />

2. The next alert to prioritize was **"Double-Extension File Creation"**, from previously I assigned it to myself and examined the details. I notice the file had both an `.mp4` and `.exe` extension. This indicates that the file contained executable code disguised as a video file. This technique is consistent with malicious code delivery. Based on this, I classified it as a **true positive** and added a comment explaining why the activity is suspicious.
   <img width="914" height="277" alt="Pasted image 20250814140556" src="https://github.com/user-attachments/assets/04daa955-68a2-4030-b3ac-f52d26a67eb9" />
   <img width="505" height="344" alt="Pasted image 20250812231804" src="https://github.com/user-attachments/assets/9642517c-771b-43e4-816b-657936330bf8" />

3. Finally, I addressed **"Download from GitHub Repository"**. The clues used to set the verdict were the description revealed that the IT team regularly uses GitHub for projects, and the URL included the keyword _react_, indicating a JavaScript library. Also, the source network information showed it originated from the developer’s network. With all of these clues indicate that this alert was triggered by an event from the IT team users possibly undergoing a project they got from GitHub. These clues indicates legitimate activity by the IT team, so I classified this as a **false positive** and commented the context.
   <img width="907" height="231" alt="Pasted image 20250814141318" src="https://github.com/user-attachments/assets/c6aed074-752a-4601-922e-d082ed2acf84" />
   <img width="504" height="344" alt="Pasted image 20250814144055" src="https://github.com/user-attachments/assets/12fe8539-0cdf-4b95-8852-4f59ac6a63ba" />

## Task 5: Conclusion
### Process Highlights
- **Monitored & Classified Alerts**: Identified 5 incoming alerts in the SOC dashboard, classified them by severity, and prioritized response to a “Potential Data Exfiltration” incident.
- **Triage & Investigation**: Validated alert properties (severity, timestamp, affected user), ruled out false positives (ex. “Unusual VPN Login Location” by M.Clark), and investigated suspicious file activity.
- **Incident Documentation**: Assigned ownership, updated ticket statuses to “In Progress,” and commented findings in alignment with SOC procedures.
- **Escalation**: For confirmed threats, escalated incidents with supporting evidence and left detailed context for SOC L2 analyst to investigate.
- **Best Practices Reinforced**:
  - Prioritize critical alerts over medium/low severity.
  - Address older critical alerts before new ones to prevent advanced stage attacks.
  - Maintain clear and concise documentation for SOC team awareness.
### Key Takeaways
- Learned to prioritize and classify alerts based on threat severity.
- Strengthened ability to distinguish between events and alerts.
- Developed a triage process that aligns with SOC analyst best practices.








 






