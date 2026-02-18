# DiskHealthCheck

PowerShell script that monitors SMART disk health using [smartmontools](https://www.smartmontools.org/) (`smartctl`). Tracks attributes over time, compares runs, and reports clear health status: **OK**, **Degraded**, or **Failing**.

## Features

- **Auto-installs smartmontools** if not already present
- **Tracks SMART attributes** over time via CSV logging
- **Delta comparison** between runs — detects active degradation
- **Threshold-based health status** — OK / Degraded / Failing with semantic exit codes
- **Supports ATA and NVMe** drives (auto-detected)
- **Configurable log path** via parameter
- Runs as a standalone script — no dependencies beyond PowerShell

## Requirements

- Windows
- PowerShell 5.1+
- Administrator privileges
- Internet access (first run only, to download smartmontools if needed)

## Usage

```powershell
# Basic — uses default log path ($env:ProgramData\DiskHealthCheck)
.\DiskHealthCheck.ps1

# Custom log path
.\DiskHealthCheck.ps1 -LogPath "D:\Logs\DiskHealth"
```

### Exit Codes

| Code | Status   | Meaning |
|------|----------|---------|
| 0    | OK       | All monitored attributes within normal ranges |
| 1    | Degraded | Early signs of deterioration detected |
| 2    | Failing  | Critical attributes indicate drive failure |

### Scheduled Task Example

Run weekly to build a history of SMART data:

```powershell
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\Scripts\DiskHealthCheck.ps1"
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 6am
Register-ScheduledTask -TaskName "DiskHealthCheck" -Action $action -Trigger $trigger -RunLevel Highest -User "SYSTEM"
```

## Monitored Attributes

| ID  | Attribute | What It Means |
|-----|-----------|---------------|
| 1   | Read Error Rate | Drive struggling to read data; early physical failure |
| 5   | Reallocated Sectors | Bad sectors replaced; any non-zero is a warning |
| 7   | Seek Error Rate | Head positioning errors; mechanical degradation |
| 10  | Spin Retry Count | Motor struggled to spin; motor failure risk |
| 184 | End-to-End Error | Internal data corruption; controller failure |
| 187 | Reported Uncorrectable Errors | Uncorrectable errors; physical media failure |
| 188 | Command Timeout | Drive became unresponsive or stalled |
| 193 | Load Cycle Count | Excessive head parking (>600k is concerning) |
| 194 | Temperature | Operating temperature in Celsius |
| 196 | Reallocation Events | Growing surface damage indicators |
| 197 | Current Pending Sector | Sectors waiting for reallocation; damage likely |
| 198 | Uncorrectable Sector Count | Permanent data loss; severe deterioration |
| 199 | UDMA CRC Error Count | Cable/connection issues |
| 231 | SSD Life Left / NVMe % Used | Percentage of rated lifetime consumed |

For NVMe drives, equivalent health metrics are mapped from the NVMe health log.

## Output

Each run produces:
- **Console output** with a summary table and health status
- **CSV log** (`SMART_Report.csv`) appended with each run for historical tracking
- **Text log** with timestamped entries for debugging

## License

[MIT](LICENSE) © Nathan Ash 2026
