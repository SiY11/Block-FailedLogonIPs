# Changelog
## [1.0.0] - 2025-05-12
- Initial release: IP blocking for Event ID 4625 with ip-api.com geolocation.
- Added configurable thresholds, log rotation, and dynamic thresholds.

## [1.1.0] - 2025-05-12
- Restructured to self-contained folder layout: `C:\BlockIPScript` with `script/` and `Logs/` subfolders.
- Updated log paths to `C:\BlockIPScript\Logs` for `BlockIP.log`, `IPAPILimits.json`, and archives/backups.
- Updated Task Scheduler action to use `C:\BlockIPScript\script\Block-FailedLogonIPs.ps1`.
- Added GitHub Actions workflow for PowerShell linting with PSScriptAnalyzer.
- Updated `README.md` and `.gitignore` to reflect new structure.

## [1.1.1] - 2025-05-12
- Small tweak to the script comments to reflect proper folder structures

## [1.2.0] - 2025-05-12
- Made script location-agnostic, allowing `BlockIPScript` folder to be placed anywhere with dynamic log paths (e.g., `<ScriptRoot>\Logs`).
- Added IP whitelist support via `allowed_ips.txt` to exempt specific IPs from blocking, with exemptions logged.
