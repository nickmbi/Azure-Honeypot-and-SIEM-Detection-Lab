# Azure-Honeypot-and-SIEM-Detection-Lab-

## Objective

Home SOC in Azure. This project involved using a free Azure subscription to create a Windows virtual machine, expose it to the internet as a honeypot, forward security logs to a centralized Log Analytics Workspace, and use Microsoft Sentinel to analyze real-world attack activity. The goal was to gain hands-on experience with cloud security monitoring, SIEM log analysis, failed-login detection, and attack visualization.

### Skills Learned

- Built a basic cloud-based SOC environment using Microsoft Azure and Microsoft Sentinel.
- Created and configured an Azure Windows virtual machine to act as a honeypot.
- Configured a Network Security Group rule to allow inbound traffic for attack simulation.
- Forwarded Windows Security Event logs into a Log Analytics Workspace.
- Used Microsoft Sentinel as a SIEM to collect, query, and investigate security events.
- Analyzed failed login attempts using Windows Event ID 4625.
- Practiced writing KQL queries to filter and investigate authentication activity.
- Enriched attacker IP address data using a GeoIP watchlist.
- Created an attack map workbook to visualize real-world attack sources.
- Improved understanding of SOC operations, log analysis, threat detection, and cloud security monitoring.

### Tools Used

- Microsoft Azure — Used to create the cloud environment and deploy the Windows virtual machine.
- Azure Virtual Machine — Used as the honeypot exposed to the internet.
- Network Security Group — Used to configure inbound traffic rules for the honeypot.
- Windows Event Viewer — Used to inspect local Windows Security logs.
- Log Analytics Workspace — Used as the central log repository for collected security events.
- Microsoft Sentinel — Used as the SIEM for log analysis, threat detection, and visualization.
- Windows Security Events via AMA Connector — Used to forward Windows Security logs into Sentinel.
- KQL — Used to query failed logins and investigate attacker activity.
- Sentinel Watchlist — Used to import GeoIP data for IP address enrichment.
- Sentinel Workbook — Used to create an attack map showing attacker locations.


## Steps
1: Azure Subscription Setup

Created a free Microsoft Azure subscription and accessed the Azure Portal. This subscription provided the cloud environment needed to deploy the honeypot virtual machine, Log Analytics Workspace, and Microsoft Sentinel instance.

2: Windows Virtual Machine Creation

Created a Windows 10 virtual machine in Azure to act as the honeypot. The VM was intentionally deployed in the cloud so it could receive real-world login attempts from the internet.

3: Network Security Group Inbound Rule

Configured the Network Security Group for the virtual machine to allow all inbound traffic. This made the VM more exposed to the internet, allowing it to collect realistic attack activity from external sources.

4: Windows Firewall Disabled

Logged into the Windows virtual machine and disabled the Windows Defender Firewall using wf.msc. This allowed more inbound traffic to reach the VM and helped generate security logs for analysis.

5: Failed Login Simulation

Attempted to log in to the virtual machine multiple times using an invalid username such as employee. These failed login attempts generated Windows Security Event logs that could later be reviewed and forwarded to Sentinel.

6: Event Viewer Security Logs

Opened Windows Event Viewer and inspected the Security logs. The failed login attempts appeared as Event ID 4625, which represents failed authentication attempts on a Windows system.

7: Log Analytics Workspace Creation

Created a Log Analytics Workspace to serve as the central log repository. This workspace collected security events from the honeypot virtual machine so the logs could be queried and analyzed in one place.

8: Microsoft Sentinel Setup

Enabled Microsoft Sentinel and connected it to the Log Analytics Workspace. Sentinel was used as the SIEM platform for monitoring, querying, and visualizing the security data collected from the VM.

9: Windows Security Events via AMA Connector

Configured the Windows Security Events via AMA connector in Microsoft Sentinel. This allowed Windows Security logs from the virtual machine to be forwarded into the Log Analytics Workspace using the Azure Monitor Agent.

10: Data Collection Rule Creation

Created a Data Collection Rule inside Sentinel to define which Windows Security Events should be collected from the VM. This step completed the log forwarding pipeline from the honeypot to the central repository.

11: Querying Failed Login Attempts with KQL

Used KQL in Log Analytics Workspace and Microsoft Sentinel to search for failed login attempts. The query filtered for Windows Security Event ID 4625.

SecurityEvent
| where EventId == 4625

This query displayed failed login activity, including timestamps, usernames, and source IP addresses.

12: Reviewing Attacker IP Addresses

Reviewed the failed login logs and identified external IP addresses attempting to authenticate to the virtual machine. These logs showed real-world brute-force activity against the exposed honeypot.

13: GeoIP Watchlist Import

Downloaded and imported the geoip-summarized.csv file into Microsoft Sentinel as a watchlist. The watchlist was named geoip and used the network field as the search key.

This watchlist allowed IP addresses from failed login attempts to be matched with geographic location data.

14: Enriching Logs with Location Data

Used KQL to match attacker IP addresses with the GeoIP watchlist. This enriched the failed login logs with geographic information such as country and region.

let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent
    | where IpAddress == "<attacker IP address>"
    | where EventID == 4625
    | order by TimeGenerated desc
    | evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network);
WindowsEvents

This helped identify where attack traffic was coming from.


15: Microsoft Sentinel Workbook Creation

Created a new Microsoft Sentinel Workbook and removed the default elements. Added a query element and used the provided JSON configuration to build an attack map.

16: Attack Map Visualization

Configured the workbook map settings to display failed login attempts by geographic location. The attack map provided a visual representation of real-world attacker activity against the Azure honeypot.

<img width="1211" height="663" alt="Attack Map" src="https://github.com/user-attachments/assets/30cbd2af-a9b5-42ed-9e75-4c3af92d349d" />


17: Final Home SOC Architecture

Completed the full Home SOC setup. The final architecture included an exposed Azure VM honeypot, Windows Security Event logs, Azure Monitor Agent, Data Collection Rule, Log Analytics Workspace, Microsoft Sentinel, GeoIP enrichment, and an attack map workbook.
