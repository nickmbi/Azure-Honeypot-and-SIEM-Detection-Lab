# Azure Honeypot & SIEM Detection Lab

## Overview

Built a cloud-based Security Operations Center using Microsoft Azure, Microsoft Sentinel, and a Windows virtual machine configured as an internet-facing honeypot. The project focused on deploying cloud infrastructure, collecting Windows Security logs, analyzing failed login attempts, enriching attack data with GeoIP information, and visualizing real-world attack activity through Microsoft Sentinel.



## Lab Architecture

```text
Internet
      │
      │
Azure Windows VM (Honeypot)
      │
Azure Monitor Agent (AMA)
      │
Data Collection Rule (DCR)
      │
Log Analytics Workspace
      │
Microsoft Sentinel
      │
GeoIP Watchlist
      │
Attack Map Workbook
```



## Tools Used

- Microsoft Azure
- Azure Virtual Machine
- Network Security Group 
- Windows Event Viewer
- Log Analytics Workspace
- Microsoft Sentinel
- Kusto Query Language
- Sentinel Workbooks
- GeoIP watchlist

# Project Walkthrough

## 1. Built the Azure Environment

Created a free Microsoft Azure subscription.

Deployed a Windows virtual machine to act as an internet-facing honeypot.

Configured a Network Security Group (NSG) to allow inbound traffic for testing.

Disabled Windows Defender Firewall to increase exposure and generate security events.

<img width="1297" height="762" alt="Firewall" src="https://github.com/user-attachments/assets/ffa59227-a3c3-4770-9e52-31ddf45904d6" />


## 2. Generated Failed Login Activity

Attempted multiple failed logins against the Windows virtual machine.

Verified Windows Security logs were generated in Event Viewer.

Confirmed failed authentication attempts appeared as **Event ID 4625**.

<img width="1402" height="785" alt="employ" src="https://github.com/user-attachments/assets/fbe30d55-e6cc-4fa8-8135-db2adb1ebce4" />


## 3. Configured Log Collection

Created a Log Analytics Workspace.

Enabled Microsoft Sentinel.

Connected the Windows virtual machine using the Azure Monitor Agent (AMA).

Created a Data Collection Rule (DCR) to forward Windows Security Events into Log Analytics.

<img width="1209" height="661" alt="Logs" src="https://github.com/user-attachments/assets/01257fb9-4429-4046-8ac0-d822f41f3ce7" />


## 4. Investigated Security Events

Used Kusto Query Language (KQL) to identify failed login attempts.

```kusto
SecurityEvent
| where EventID == 4625
```

Reviewed:

- Failed login attempts
- Usernames
- Source IP addresses
- Event timestamps



## 5. Added GeoIP Enrichment

Imported the GeoIP watchlist into Microsoft Sentinel.

Matched attacker IP addresses with geographic location data.

Enriched failed login events with country and region information.

<img width="1212" height="667" alt="Geo Ip" src="https://github.com/user-attachments/assets/0e15c2c6-0ae5-44fb-ab63-5252ac4658c8" />


## 6. Built an Attack Map

Created a Microsoft Sentinel Workbook.

Configured a map visualization to display failed login attempts by geographic location.

Observed real-world attack traffic targeting the Azure honeypot.

<img width="1211" height="663" alt="Attack Map" src="https://github.com/user-attachments/assets/cd475c38-60e8-4717-a291-8ce4071ce4fb" />


# Skills Learned

- Cloud Security
- Microsoft Azure
- Microsoft Sentinel
- Windows Security Event Analysis
- Log Analytics Workspace
- Data Collection Rules
- Kusto Query Language 
- Network Security Groups 
- Threat Monitoring
- Security Event Visualization

