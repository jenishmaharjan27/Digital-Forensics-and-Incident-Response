# Digital Forensics and Incident Response


**Author:** Jenish Maharjan  
**Role:** Forensic Analyst  

---

## Scenario

A company has detected unusual activity on its servers, leading to data leakage. You have been hired as a forensic analyst to investigate the breach, identify the attacker’s method, and propose security improvements.

---

## 1. Introduction to Digital Forensics

Digital Forensics is the structured scientific process of investigating cybercrimes by collecting, investigating, and preserving evidence found in digital devices recovered from crime scenes. The main objective of digital forensics is to collect and analyze digital evidence while maintaining integrity and legal relevancy in court. The validity of a forensic investigation relies heavily on the **Chain of Custody**, which ensures that evidence is handled, stored, and documented in a way that prevents tampering.

Digital forensics uses various specialized techniques to uncover and reconstruct events after an incident:

- **Disk Imaging:** Creating an exact bit-by-bit copy of a storage device without altering the evidence.  
- **Hashing:** Generating a unique fixed-length hash value to verify data integrity and detect changes.  
- **Log Analysis:** Examining system and network logs to identify suspicious activity, track unauthorized access, and reconstruct events.  
- **Timeline Analysis:** Organizing digital artifacts chronologically to reveal the sequence and timing of actions.  
- **File Recovery:** Recovering deleted, corrupted, or hidden files to uncover potential evidence.  
- **Malware Analysis:** Examining malicious programs to understand their behavior, origin, and impact.

Together, these techniques provide a comprehensive approach to uncovering, preserving, and analyzing digital evidence critical for solving cybercrimes and responding to security incidents.

**Incident Response (IR)** focuses on acting quickly to limit damage, contain threats, and restore operations. It is a structured approach to detecting, managing, and mitigating cyber incidents to minimize damage and accelerate recovery. IR includes preparation, detection, containment, eradication, recovery, and post-incident learning.

The **NIST Incident Response Framework** consists of the following phases:

1. **Preparation** – Developing policies, playbooks, roles, and training.  
2. **Detection and Analysis** – Identifying suspicious activities and assessing their impact.  
3. **Containment, Eradication, and Recovery** – Isolating affected systems, removing threats, and restoring operations.  
4. **Post-Incident Activity** – Documenting incidents, evaluating response effectiveness, and improving defenses.

Digital forensics and incident response together form a crucial cybersecurity defense. Forensics explains *how* attacks occurred, while incident response focuses on *minimizing impact*. An integrated approach ensures effective incident handling, evidence preservation, and continuous security improvement.

---

## 2. Forensic Data Collection

In this investigation, **Wazuh**, an open-source security monitoring and log analysis tool, was used. Wazuh collected detailed endpoint activity and centralized it for analysis. It enabled detection of unusual behavior, tracking of system changes, and identification of potential security incidents through real-time alerts and correlation rules.

By monitoring the Windows machine through Wazuh, sufficient evidence was gathered to understand the breach and reconstruct events leading to the incident.

### 2.1 Setup Overview

- **Wazuh Server:** Ubuntu  
- **Attack Machine:** Kali Linux  
- **Victim Machine:** Windows 10  

The Wazuh Agent installed on the Windows machine was configured to collect extensive system activity logs, including user actions, system changes, and application behavior. These logs were continuously forwarded to the Wazuh server for centralized monitoring and analysis.

<img width="975" height="511" alt="image" src="https://github.com/user-attachments/assets/1bd04b8a-141a-4f1e-9bed-eca52a506a5d" />
<img width="975" height="333" alt="image" src="https://github.com/user-attachments/assets/8295839c-9cd9-4649-9ca2-f619de289f0f" />
<img width="975" height="253" alt="image" src="https://github.com/user-attachments/assets/e2492f3e-4ef7-43fb-8dc0-e529b04cdad7" />
*Figure 2.1: Successful installation of the Wazuh server on the Ubuntu system used for centralized security monitoring.*
<br><br>

<img width="975" height="444" alt="image" src="https://github.com/user-attachments/assets/d39ea06d-b03f-4c7a-bcd2-c37b5baf71aa" />
*Figure 2.2: Wazuh manager and associated services running successfully after installation on the Ubuntu server.*
<br><br>

<img width="975" height="523" alt="image" src="https://github.com/user-attachments/assets/ff9671bb-6253-47dc-a35c-994501a4c2a6" />
*Figure 2.3: Wazuh dashboard displaying centralized security monitoring and real-time alerts collected from the Windows victim system.*
<br><br>

<img width="975" height="510" alt="image" src="https://github.com/user-attachments/assets/17389bb3-1b4d-4441-a353-d915a14ccf11" />
<img width="975" height="511" alt="image" src="https://github.com/user-attachments/assets/c0461345-8353-4884-8892-de2f92d58aa6" />
<img width="975" height="514" alt="image" src="https://github.com/user-attachments/assets/a19ffd77-29ab-440e-80cb-a3d54c358448" />
*Figure 2.3: Wazuh Windows agent deployed and activated using windows powershell for capturing endpoint activities and detecting unauthorized access during the investigation.*
<br><br>


### 2.2 Suspicious Activity Identified

The investigation revealed that the attacker gained access using a **reverse shell exploitation technique**. After gaining access, the attacker downloaded sensitive information and attempted to delete files to cover their tracks. Evidence of unauthorized access, data exfiltration, and file deletion was detected through Wazuh alerts and system logs.

<img width="975" height="521" alt="image" src="https://github.com/user-attachments/assets/8e025047-70d7-403a-a606-187928a1d56e" />
*Figure 2.4: Detection of malicious activity by Wazuh through real-time security monitoring and alert correlation.*
<br><br>

<img width="975" height="522" alt="image" src="https://github.com/user-attachments/assets/653f96d3-15a1-4fc9-a538-64b6192f4706" />
<img width="975" height="525" alt="image" src="https://github.com/user-attachments/assets/30e04776-6840-4a36-a1c9-bcb120b920f6" />
<img width="975" height="524" alt="image" src="https://github.com/user-attachments/assets/85daa5b6-ff8e-4b01-a660-9f8d6cade65d" />
*Figure 2.5: Wazuh log entries capturing attacker activity and system events related to the intrusion.*
<br><br>

<img width="975" height="513" alt="image" src="https://github.com/user-attachments/assets/ec9a9ea6-f413-4bde-b5c8-9b8b165c63c7" />
<img width="975" height="515" alt="image" src="https://github.com/user-attachments/assets/fb13a386-b43c-45d4-9fce-c4204298974e" />
*Figure 2.6: File Integrity Monitoring (FIM) logs showing unauthorized file modifications on the victim system.*
<br><br>

### 2.3 Key Findings

- Unauthorized reverse shell access was established on the victim system.  
- A suspicious executable was downloaded on the victim machine.  
- Sensitive files were exfiltrated.  
- Files were intentionally deleted to hide activity.  
- System logs were cleared to conceal malicious actions.

For a detailed demonstration of the attack vector used in this investigation, including payload creation, reverse shell setup, and attacker actions, visit the following repository:

**[Attack Vector Project Repository](https://github.com/jenishmaharjan27/Reverse-Shell-Exploitation)**

---

## 3. File Recovery and Analysis

Specialized forensic tools such as **FTK Imager** and **Autopsy** were used to examine the acquired disk image. The goal was to recover deleted files, identify malicious activity, and assess unauthorized access.

### 3.1 Disk Image Creation Using FTK Imager

FTK Imager was used to create a forensic disk image of the compromised system. The tool preserved evidence integrity by generating hash values for verification. This disk image served as the primary evidence source for further analysis.

<img width="975" height="507" alt="image" src="https://github.com/user-attachments/assets/d7eb8d0c-ca56-4248-82a2-e91555b1b0a6" />
<img width="975" height="505" alt="image" src="https://github.com/user-attachments/assets/6540d007-1e79-47ed-83e4-e4a6f338b226" />
<img width="975" height="507" alt="image" src="https://github.com/user-attachments/assets/12c2f3de-10ca-48eb-9a23-46b6f1b31279" />
<img width="975" height="526" alt="image" src="https://github.com/user-attachments/assets/449b2be2-a7dd-4a69-8d25-9ce9945a26ea" />
*Figure 3.1: Creation of a forensic system disk image to preserve evidence integrity for further analysis.*
<br><br>

### 3.2 Analysis Using Autopsy

The disk image was imported into Autopsy for in-depth analysis. Autopsy modules were used to inspect file systems, analyze metadata, and recover deleted files. Despite attempts to hide evidence by deleting files and clearing logs, recovered artifacts indicated unauthorized activity.

<img width="975" height="520" alt="image" src="https://github.com/user-attachments/assets/128673cf-2400-46c2-b4f6-8c299b1bda11" />
*Figure 3.2: Creation of a new forensic case in Autopsy to analyze the acquired system disk image.*
<br><br>

<img width="975" height="523" alt="image" src="https://github.com/user-attachments/assets/c39ff5b6-fd9f-4527-8a53-b257dc05023a" />
<img width="975" height="523" alt="image" src="https://github.com/user-attachments/assets/c8004bbc-54d6-467d-8195-fc0d9d461dcd" />
*Figure 3.3: Autopsy analysis results displaying recovered artifacts and indicators of unauthorized activity.*
<br><br>

### 3.3 Identification of Malicious Software

A suspicious executable recovered from the disk image was isolated and analyzed. The file was submitted to **VirusTotal**, where multiple antivirus engines classified it as **Trojan.Marte/Shellcode**. This confirmed the file as a malicious payload used to establish the reverse shell and gain unauthorized access.

<img width="975" height="527" alt="image" src="https://github.com/user-attachments/assets/933b4379-82c4-45a5-9018-fe6ca5e028b5" />
<img width="975" height="526" alt="image" src="https://github.com/user-attachments/assets/5b29f6fd-09d0-4e7e-b598-2985b30a5b6f" />
*Figure 3.4: Malware analysis performed using VirusTotal to identify and classify the extracted malicious executable.*
<br><br>


---

## 4. Identifying the Attack and Its Impact

### 4.1 Determining the Initial Access Vector

The attacker gained access through a malicious executable unknowingly downloaded by the victim. Once executed, the malware established a reverse shell connection, allowing remote control of the system without the victim’s knowledge.

### 4.2 Tracking the Attack Through Logs and File System Changes

Although logs were partially cleared, file system metadata and remnants provided critical evidence. Autopsy revealed unauthorized file access, deletion of user files, and manipulation of system artifacts. These findings confirmed that the compromise occurred immediately after execution of the malicious executable.

---

## 5. Incident Response and Security Measures

### 5.1 Preventive Security Measures

To reduce future risk:

- Deploy strong endpoint protection solutions.  
- Train users to avoid downloading unknown or suspicious files.  
- Restrict administrative privileges.  
- Monitor abnormal outbound connections using SIEM tools like Wazuh.  
- Maintain regular patching, firewall enforcement, and system hardening.  

### 5.2 Best Practices for Incident Response

1. **Identification:** Detect anomalies through monitoring and alerts.  
2. **Containment:** Isolate affected systems and block malicious access.  
3. **Eradication:** Remove malware, unauthorized accounts, and persistence mechanisms.  
4. **Recovery:** Restore systems from clean backups and apply patches.  
5. **Lessons Learned:** Document incidents, update policies, and improve monitoring.

A structured incident response process minimizes damage, reduces downtime, and strengthens organizational resilience.

---

## Conclusion

This Digital Forensics and Incident Response project demonstrated a complete investigation of a compromised Windows VM. FTK Imager was used for disk acquisition, and Autopsy enabled recovery of deleted files and analysis of system artifacts. The malicious executable, identified as **Trojan.Marte/Shellcode** via VirusTotal, enabled reverse shell exploitation, unauthorized access, and log tampering. The project highlighted the importance of evidence preservation, systematic forensic analysis, and structured incident response, providing practical insight into detecting attacks and preventing future breaches.
