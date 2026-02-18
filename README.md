# DiskHealthCheck

PowerShell script that monitors SMART disk health using [smartmontools](https://www.smartmontools.org/) (`smartctl`). Tracks attributes over time, compares runs, and reports clear health status: **OK**, **Degraded**, or **Failing**.

Designed for **Datto RMM** (writes results to UDF custom fields) but works perfectly as a standalone script on any Windows machine.

📝 **[Read the full blog post](https://nathanash.com/blog/disk-health-check/)** for a deep dive into how it works.

## Features

- **Auto-installs smartmontools** if not already present
- **Tracks SMART attributes** over time via CSV logging
- **Delta comparison** between runs — detects active degradation
- **Threshold-based health status** — OK / Degraded / Failing with semantic exit codes
- **Supports ATA and NVMe** drives (auto-detected via `smartctl --scan`)
- **Datto RMM integration** — writes summary to UDF custom fields via CentraStage registry
- **Standalone compatible** — gracefully skips RMM features when not in a Datto context
- **Structured logging** — timestamped log files for debugging

## Requirements

- Windows
- PowerShell 5.1+
- Administrator privileges
- Internet access (first run only, to download smartmontools if needed)

## Usage

### Standalone

```powershell
# Run with defaults (logs to $env:ProgramData\DiskHealthCheck\log)
.\DiskHealthCheck.ps1
```

### Datto RMM Component

Deploy as a Datto RMM component. Configure these **component variables** as needed:

| Variable | Default | Description |
|----------|---------|-------------|
| `UdfNumber` | `8` | UDF custom field number to write the health summary to |
| `CsvLogPath` | `$env:ProgramData\DiskHealthCheck\log` | Directory for CSV report history |

The script writes a compact summary to the UDF field, e.g.:
```
OK | Samsung SSD 980 | 42C | Life: 3%
DEGRADED | WDC WD10EZEX | 55C | 2 changed
```

### Exit Codes

| Code | Status | Meaning |
|------|--------|---------|
| 0 | OK | All monitored attributes within normal ranges |
| 1 | Degraded | Early signs of deterioration detected |
| 2 | Failing | Critical attributes indicate drive failure |

### Scheduled Task (Standalone)

Run weekly to build a history of SMART data:

```powershell
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\Scripts\DiskHealthCheck.ps1"
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 6am
Register-ScheduledTask -TaskName "DiskHealthCheck" -Action $action -Trigger $trigger -RunLevel Highest -User "SYSTEM"
```

## Monitored Attributes

| ID | Attribute | What It Means |
|----|-----------|---------------|
| 1 | Read Error Rate | Drive struggling to read data; early physical failure |
| 5 | Reallocated Sectors | Bad sectors replaced; any non-zero is a warning |
| 7 | Seek Error Rate | Head positioning errors; mechanical degradation |
| 10 | Spin Retry Count | Motor struggled to spin; motor failure risk |
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

For NVMe drives, equivalent health metrics are mapped from the NVMe health information log.

## How It Works

1. **Identifies the OS drive** (C: partition → physical disk number)
2. **Finds or installs smartctl** (smartmontools) automatically
3. **Queries SMART data** via `smartctl -a --json` (ATA or NVMe)
4. **Loads previous run** from CSV for delta comparison
5. **Evaluates thresholds** — flags attributes as Degraded or Failing
6. **Detects changes** — attributes that increased since last run trigger warnings
7. **Logs results** to CSV (append) and timestamped log file
8. **Writes UDF** summary to Datto RMM (if running in Datto context)
9. **Exits with semantic code** (0/1/2) for RMM alerting

## Output

Each run produces:
- **Console output** — summary table with health status
- **CSV log** (`SMART_Report.csv`) — appended each run for historical tracking
- **Component log** — timestamped entries for debugging
- **UDF field** (Datto RMM only) — compact status string for dashboard visibility

## License

[MIT](LICENSE) © Nathan Ash 2026
