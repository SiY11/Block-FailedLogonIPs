# Block-FailedLogonIPs

PowerShell script to monitor Event ID 4625 (failed logon attempts) on a Windows server or client, such as a game server. It auto-blocks non-US IPs on the first attempt and US IPs with more than a configurable number of attempts (default: 5) in a configurable time window (default: 10 minutes). Uses ip-api.com for geolocation with batch queries for efficiency.

## Features
- Auto-blocks non-US IPs on first attempt, US IPs with >5 attempts in 10 minutes.
- Checks existing firewall rules before API calls to minimize requests.
- Uses ip-api.com (45 req/min for single queries, 15 req/min for batch queries).
- Logs new rules, existing rules, and errors to a ``Logs`` folder relative to the script's location (e.g., ``C:\BlockIPScript\Logs\BlockIP.log``).
- Configurable thresholds for attempts and time window, with dynamic parameters for manual runs.
- Log rotation (10 MB max) with unlimited retention (enabled).
- Rate limit tracking in a ``Logs`` folder (e.g., ``C:\BlockIPScript\Logs\IPAPILimits.json``) with daily backups.
- Supports an IP whitelist via ``allowed_ips.txt`` to exempt specific IPs from blocking.

## Prerequisites
- Windows 10 Pro or Server with PowerShell 5.1.
- Administrative privileges for creating Windows Firewall rules.
- Write access to the ``Logs`` folder in the script’s parent directory (e.g., ``C:\BlockIPScript\Logs``).
- Internet access for ip-api.com API calls.

## Installation
- Copy file structure to a local folder of your choice.

## Usage
### Manual Run
- Run the script with optional threshold parameters:
    ```powershell
    .\Block-FailedLogonIPs.ps1 -AttemptThreshold 3 -TimeWindowMinutes 5
    ```

### Task Scheduler
- Create a task triggered by Event ID 4625 (Security log) with a 10-second delay.
- Use a local service account with admin rights (e.g., IPBlockService).
- Set the action to: 
    ```powershell 
    powershell.exe -ExecutionPolicy Bypass -File "C:\BlockIPScript\script\Block-FailedLogonIPs.ps1" 
    ```
- See script header for setup details.

## Configuration
##### Edit the script’s configuration section to adjust:
- ``$AttemptThreshold``: Default 5 attempts for US IPs.
- ``$TimeWindowMinutes``: Default 10-minute window.
- ``$LogRetentionUnlimited``: Set to true for unlimited log retention (currently enabled).
- ``$LogRetentionDays``: Days to keep archived logs if not unlimited (default: 365).
- ``$MaxLogSizeMB``: Max log size before rotation (default: 10 MB).
- ``$LimitsBackupRetentionDays``: Days to keep limits file backups (default: 1).

## Whitelist
- Add IP's to the ``allowed_ips.txt`` file to exempt specific IPs from blocking. List one IPv4 address per line:

## Logs
- **Event Logs**: ``\BlockIPScript\Logs\BlockIP.log`` (new rules, existing rules, errors).
- **Rate Limits**: ``\BlockIPScript\Logs\IPAPILimits.json`` (API call limits).
- **Archives**: ``\BlockIPScript\Logs\BlockIP_YYYYMMDD.log.zip`` (rotated logs, unlimited retention).
- **Backups**: ``\BlockIPScript\Logs\IPAPILimits_YYYYMMDD.json`` (1-day retention).

##### Example Log Output

```plaintext
[2025-05-12 07:09:27] INFO : IP 38.255.59.5 found in violation (IP is outside the USA (country: United Kingdom))
[2025-05-12 07:09:27] INFO : "Block_IP_38.255.59.5" rule created in Windows firewall
[2025-05-12 07:23:26] INFO : IP 212.22.161.179 found in violation (IP is outside the USA (country: Kenya))
[2025-05-12 07:23:27] INFO : "Block_IP_212.22.161.179" rule created in Windows firewall
[2025-05-12 07:46:27] INFO : IP 80.94.95.203 found in violation (IP is outside the USA (country: Hungary))
[2025-05-12 07:46:27] INFO : "Block_IP_80.94.95.203" rule created in Windows firewall
[2025-05-12 07:46:49] INFO : Rule already exists for IP: 80.94.95.203
[2025-05-12 08:51:20] INFO : IP 179.60.146.60 found in violation (IP is outside the USA (country: The Netherlands))
[2025-05-12 08:51:21] INFO : "Block_IP_179.60.146.60" rule created in Windows firewall
[2025-05-12 08:51:24] INFO : Rule already exists for IP: 179.60.146.60
[2025-05-12 09:29:01] INFO : IP 193.29.13.6 found in violation (IP is outside the USA (country: Romania))
[2025-05-12 09:29:02] INFO : "Block_IP_193.29.13.6" rule created in Windows firewall
[2025-05-12 09:29:06] INFO : Rule already exists for IP: 193.29.13.6
[2025-05-12 09:39:18] INFO : IP 91.199.163.12 found in violation (IP is outside the USA (country: Lithuania))
[2025-05-12 09:39:18] INFO : "Block_IP_91.199.163.12" rule created in Windows firewall
[2025-05-12 09:39:21] INFO : Rule already exists for IP: 91.199.163.12
```

## License
MIT License (see LICENSE file).

## Contributing
For private use, contact the author (SiY11@hotmail.com). For public repositories, open an issue or submit a pull request.
