# Threat Hunt Report // Unauthorized T<img height="50" alt="onion" src="https://github.com/user-attachments/assets/8fed5042-f72a-4d83-bf2c-576e7a530858" />R Usage


**Detection of Unauthorized TOR Browser Installation and Use on Workstation: ws-1650**

## Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

## Platforms and Languages Leveraged

- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint (MDE)
- Kusto Query Language (KQL)
- Tor Browser

## TOR-Related IoC Discovery Plan

1. Check `DeviceFileEvents` for any `tor(.exe)` or `firefox(.exe)` file events
2. Check `DeviceProcessEvents` for any signs of installation or usage
3. Check `DeviceNetworkEvents` for any signs of outgoing connections over known TOR ports

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the `DeviceFileEvents` table for ANY file that had the string "tor" in it and discovered what looks like the user "shari_higgenbottom" downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called "tor-shopping-list.txt" on the desktop at `2026-05-04T21:01:10.9698279Z`. These events began at `2026-05-03T19:16:25.3417183Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "ws-1650"
| where InitiatingProcessAccountName == "shari_higgenbottom"
| where FileName contains "tor"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
Results:
<img width="1248" height="844" alt="DeviceFileEvents_tor_string_search" src="https://github.com/user-attachments/assets/5a02ee44-31b3-43e6-bcca-1d7788b278b1" />

### 2. Searched the `DeviceProcessEvents` Table

Searched the `DeviceProcessEvents` table for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-15.0.11.exe". At `2026-05-04T20:05:36.3830487Z`, employee account shari_higgenbottom on the 'ws-1650' device ran the file `tor-browser-windows-x86_64-portable-15.0.11.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "ws-1650"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.11.exe"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine
```
Results:
<img width="1258" height="450" alt="DeviceProcessEvents_tor_install_file" src="https://github.com/user-attachments/assets/21666225-d0dd-42b0-afc7-e91dac611446" />

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the `DeviceProcessEvents` table for any indication that user "shari_higgenbottom" actually opened the TOR browser. There was evidence that they did open it at `2026-05-04T20:06:43.6949055Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "ws-1650"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1796" height="912" alt="tor_usage_list" src="https://github.com/user-attachments/assets/bea15edd-24d3-4e25-897b-6875012c4023" /><br>
<img width="1162" height="336" alt="tor_browser_usage" src="https://github.com/user-attachments/assets/97d485ca-8ac4-4a93-8447-1f31210a63b4" />

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the `DeviceNetworkEvents` table for any indication the TOR browser was used to establish a connection using any of the known TOR port numbers. At 3:25 PM on May 6, 2026, the account shari_higgenbottom on device ws-1650 successfully established a connection to remote IP `94.130.52.190` on port `9030`. The connection was initiated by process `tor.exe`, located at `C:\users\shari_higgenbottom\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a few other connections to sites over port 443.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "ws-1650"
| where InitiatingProcessAccountName != "system"
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
```
<img width="1156" height="544" alt="DeviceNetworkEvents_tor_connections" src="https://github.com/user-attachments/assets/3e8e531b-ee52-47a2-a53a-00b757ef5a87" />

## Chronological Events

### 1. File Download — TOR Installer
- **Timestamp:** `2026-05-03T19:16:25.3417183Z`
- **Event:** The account shari_higgenbottom on device ws-1650 downloaded a file named `tor-browser-windows-x86_64-portable-15.0.11.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\shari_higgenbottom\Downloads\tor-browser-windows-x86_64-portable-15.0.11.exe`

### 2. Process Execution — TOR Browser Installation
- **Timestamp:** `2026-05-04T20:05:36.3830487Z`
- **Event:** The account shari_higgenbottom executed `tor-browser-windows-x86_64-portable-15.0.11.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.11.exe /S`
- **File Path:** `C:\Users\shari_higgenbottom\Downloads\tor-browser-windows-x86_64-portable-15.0.11.exe`

### 3. Process Execution — TOR Browser Launch
- **Timestamp:** `2026-05-04T20:06:43.6949055Z`
- **Event:** The account shari_higgenbottom opened the TOR browser. Subsequent processes associated with TOR browser including `firefox.exe` and `tor.exe` were also created, indicating the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\shari_higgenbottom\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection — TOR Network
- **Timestamp:** `2026-05-06T15:25:48Z`
- **Event:** The account shari_higgenbottom on device ws-1650 successfully established a connection to remote IP `94.130.52.190` on port `9030` using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `C:\users\shari_higgenbottom\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. File Creation — TOR Shopping List
- **Timestamp:** `2026-05-04T21:01:10.9698279Z`
- **Event:** The account shari_higgenbottom created a file named `tor-shopping-list.txt` on the desktop, potentially indicating notes related to TOR browser activity.
- **Action:** File creation detected.
- **File Path:** `C:\Users\shari_higgenbottom\Desktop\tor-shopping-list.txt`

## Summary

The account "shari_higgenbottom" on the "ws-1650" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file. The full sequence from download to silent install to active network connections confirms intentional installation and use rather than accidental execution.

## Response Taken

TOR usage was confirmed on endpoint ws-1650. The device was isolated and the user's direct manager was notified.
