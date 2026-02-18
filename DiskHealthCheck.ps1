#Requires -RunAsAdministrator
<#
.SYNOPSIS
    SMART disk health monitoring script using smartmontools/smartctl.

.DESCRIPTION
    Monitors SMART attributes on the OS drive, tracks values over time via CSV logging,
    performs delta comparison between runs, and reports threshold-based health status
    (OK / Degraded / Failing).

    Automatically installs smartmontools if not already present.

.PARAMETER LogPath
    Directory for CSV logs and script logs. Defaults to $env:ProgramData\DiskHealthCheck

.EXAMPLE
    .\DiskHealthCheck.ps1
    Run with default log path.

.EXAMPLE
    .\DiskHealthCheck.ps1 -LogPath "D:\Logs\DiskHealth"
    Run with a custom log directory.

.NOTES
    Author: Nathan Ash
    License: MIT
    Requires: Windows, PowerShell 5.1+, Administrator privileges
#>

[CmdletBinding()]
param(
    [string]$LogPath = "$env:ProgramData\DiskHealthCheck"
)

# ----------------------------------------
# Logging
# ----------------------------------------
$script:LogFile = Join-Path $LogPath "DiskHealthCheck-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Message,

        [ValidateSet('INFO', 'WARN', 'ERROR', 'DEBUG')]
        [string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry = "[$timestamp] [$Level] $Message"

    $logDir = Split-Path $script:LogFile -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }

    Add-Content -Path $script:LogFile -Value $entry -Encoding UTF8

    switch ($Level) {
        'ERROR' { Write-Error $Message }
        'WARN'  { Write-Warning $Message }
        'DEBUG' { Write-Verbose $Message -Verbose }
        default { Write-Output $entry }
    }
}

# ----------------------------------------
# Require Administrator privileges
# ----------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) {
    Write-Host 'ERROR: This script must be run as Administrator.' -ForegroundColor Red
    exit 1
}

# Ensure log directory exists
if (!(Test-Path $LogPath)) { New-Item -ItemType Directory -Path $LogPath -Force | Out-Null }

$CsvFile = Join-Path $LogPath "SMART_Report.csv"

Write-Log "Starting SMART disk health check for OS drive"

# ----------------------------------------
# SMART ATTRIBUTES OF INTEREST
# ----------------------------------------
$SmartAttributes = @{
    1   = @{ Name = "Read Error Rate";              Meaning = "High values indicate the drive is struggling to read data; early physical failure." }
    5   = @{ Name = "Reallocated Sectors";           Meaning = "Bad sectors that have been replaced; any non-zero value is a warning." }
    7   = @{ Name = "Seek Error Rate";               Meaning = "Head positioning errors; mechanical degradation." }
    10  = @{ Name = "Spin Retry Count";              Meaning = "Drive motor struggled to spin; motor failure risk." }
    184 = @{ Name = "End-to-End Error";              Meaning = "Data corruption detected internally; controller failure." }
    187 = @{ Name = "Reported Uncorrectable Errors"; Meaning = "Errors the drive could not correct; physical media failure." }
    188 = @{ Name = "Command Timeout";               Meaning = "Drive became unresponsive or stalled." }
    193 = @{ Name = "Load Cycle Count";              Meaning = "High values can indicate excessive head parking (>600,000 is concerning)." }
    194 = @{ Name = "Temperature";                   Meaning = "Drive operating temperature in Celsius." }
    196 = @{ Name = "Reallocation Events";           Meaning = "Count of reallocation attempts; indicators of growing surface damage." }
    197 = @{ Name = "Current Pending Sector";        Meaning = "Sectors waiting for reallocation; physical damage likely." }
    198 = @{ Name = "Uncorrectable Sector Count";    Meaning = "Permanent data loss in sectors; severe deterioration." }
    199 = @{ Name = "UDMA CRC Error Count";          Meaning = "Cable/connection issues (not physical damage but relevant)." }
    231 = @{ Name = "SSD Life Left / NVMe % Used";   Meaning = "Percentage of rated lifetime consumed. 100 = end of rated life." }
}

# ----------------------------------------
# Get OS Disk Number
# ----------------------------------------
$osVolume = Get-Partition -DriveLetter C | Get-Disk
$DiskNumber = $osVolume.Number
Write-Log "OS disk identified as Disk Number: $DiskNumber"

# ----------------------------------------
# Find or Install smartctl
# ----------------------------------------
function Get-SmartctlPath {
    $searchPaths = @(
        "C:\Program Files\smartmontools\bin\smartctl.exe",
        "C:\Program Files (x86)\smartmontools\bin\smartctl.exe"
    )
    foreach ($p in $searchPaths) {
        if (Test-Path $p) { return $p }
    }
    $inPath = Get-Command smartctl.exe -ErrorAction SilentlyContinue
    if ($inPath) { return $inPath.Source }
    return $null
}

function Install-Smartmontools {
    Write-Log "smartmontools not found - attempting automatic installation" | Out-Null

    $installerUrl = "https://sourceforge.net/projects/smartmontools/files/smartmontools/7.4/smartmontools-7.4-1.win32-setup.exe/download"
    $installerPath = Join-Path $env:TEMP "smartmontools-setup.exe"

    try {
        Write-Log "Downloading smartmontools installer..." | Out-Null
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $wc = New-Object System.Net.WebClient
        $wc.DownloadFile($installerUrl, $installerPath)

        if (!(Test-Path $installerPath)) {
            throw "Download failed - installer not found at $installerPath"
        }

        Write-Log "Running silent install..." | Out-Null
        $proc = Start-Process -FilePath $installerPath -ArgumentList "/S" -Wait -PassThru
        if ($proc.ExitCode -ne 0) {
            throw "Installer exited with code $($proc.ExitCode)"
        }

        Remove-Item $installerPath -Force -ErrorAction SilentlyContinue

        $smartctlPath = Get-SmartctlPath
        if ($smartctlPath) {
            Write-Log "smartmontools installed successfully: $smartctlPath" | Out-Null
            return $smartctlPath
        }
        else {
            throw "Installation completed but smartctl.exe not found"
        }
    }
    catch {
        Write-Log "Failed to install smartmontools: $_" -Level ERROR | Out-Null
        Remove-Item $installerPath -Force -ErrorAction SilentlyContinue
        return $null
    }
}

$SmartctlExe = Get-SmartctlPath
if (-not $SmartctlExe) {
    $SmartctlExe = Install-Smartmontools
}

if (-not $SmartctlExe) {
    Write-Log "smartmontools could not be found or installed. Cannot retrieve SMART data." -Level ERROR
    exit 2
}

Write-Log "Using smartctl: $SmartctlExe"

# ----------------------------------------
# Get SMART data via smartctl JSON
# ----------------------------------------
$DevicePath = "\\.\PhysicalDrive$DiskNumber"
$DeviceType = $null
try {
    $scanOutput = & $SmartctlExe --scan 2>&1
    $driveLetter = [char]([int][char]'a' + $DiskNumber)
    $scanLine = $scanOutput | Where-Object { $_ -match "^/dev/sd$driveLetter\b" }
    if ($scanLine -match '^(/dev/sd\w+)\s+-d\s+(\S+)') {
        $DevicePath = $Matches[1]
        $DeviceType = $Matches[2]
        Write-Log "Scan detected device: $DevicePath (type: $DeviceType)"
    }
}
catch {
    Write-Log "Could not run --scan to detect device, falling back to \\.\PhysicalDrive$DiskNumber" -Level WARN
}

Write-Log "Querying SMART data for device: $DevicePath"

try {
    $smartctlArgs = @('-a', '--json=c')
    if ($DeviceType) {
        $smartctlArgs += @('-d', $DeviceType)
    }
    $smartctlArgs += $DevicePath

    $jsonRaw = & $SmartctlExe @smartctlArgs 2>&1

    # smartctl exit codes use bit flags. Bits 0-1 are fatal errors.
    if ($LASTEXITCODE -band 3) {
        throw "smartctl returned fatal error (exit code $LASTEXITCODE): $($jsonRaw -join "`n")"
    }

    $jsonString = $jsonRaw -join "`n"
    $SmartData = $jsonString | ConvertFrom-Json
}
catch {
    Write-Log "Failed to run smartctl: $_" -Level ERROR
    exit 2
}

# ----------------------------------------
# Parse SMART attributes from JSON
# ----------------------------------------
$CurrentValues = @{}

if ($SmartData.ata_smart_attributes -and $SmartData.ata_smart_attributes.table) {
    Write-Log "Drive reports ATA SMART attributes"
    foreach ($attr in $SmartData.ata_smart_attributes.table) {
        $attrId = [int]$attr.id
        if ($SmartAttributes.ContainsKey($attrId)) {
            $CurrentValues[$attrId] = [long]$attr.raw.value
        }
    }
}
elseif ($SmartData.nvme_smart_health_information_log) {
    Write-Log "Drive reports NVMe health information"
    $nvme = $SmartData.nvme_smart_health_information_log

    $CurrentValues[194] = $(
        if ($nvme.temperature -is [int]) { $nvme.temperature }
        elseif ($nvme.temperature_sensors) { $nvme.temperature_sensors[0] }
        else { $null }
    )
    $CurrentValues[187] = $nvme.media_errors
    $CurrentValues[1]   = $nvme.num_err_log_entries
    $CurrentValues[231] = $nvme.percentage_used
}
else {
    Write-Log "No recognisable SMART attribute data found in smartctl output" -Level WARN
}

# Fill missing attributes with $null
foreach ($id in $SmartAttributes.Keys) {
    if (-not $CurrentValues.ContainsKey($id)) {
        $CurrentValues[$id] = $null
    }
}

if ($SmartData.model_name)   { Write-Log "Drive model: $($SmartData.model_name)" }
if ($SmartData.serial_number) { Write-Log "Drive serial: $($SmartData.serial_number)" }

$supportedCount = ($CurrentValues.Values | Where-Object { $_ -ne $null }).Count
Write-Log "SMART data retrieved - $supportedCount of $($SmartAttributes.Count) tracked attributes reported by drive"

# ----------------------------------------
# Load previous run if exists
# ----------------------------------------
$Previous = @{}
if (Test-Path $CsvFile) {
    $Raw = Import-Csv $CsvFile | Where-Object { $_.DiskNumber -eq $DiskNumber }
    if ($Raw) {
        foreach ($id in $SmartAttributes.Keys) {
            $attrPrev = $Raw | Where-Object { $_.AttributeID -eq $id } | Sort-Object Timestamp -Descending | Select-Object -First 1
            if ($attrPrev) { $Previous[$id] = [long]$attrPrev.RawValue }
        }
        Write-Log "Previous SMART data loaded for comparison"
    }
}

# ----------------------------------------
# Build Table
# ----------------------------------------
$Table = foreach ($id in $SmartAttributes.Keys) {
    [PSCustomObject]@{
        AttributeID = $id
        Attribute   = $SmartAttributes[$id].Name
        RawValue    = $CurrentValues[$id]
        Meaning     = $SmartAttributes[$id].Meaning
        Previous    = $Previous[$id]
        Change      = if ($Previous.ContainsKey($id) -and $null -ne $CurrentValues[$id]) { $CurrentValues[$id] - $Previous[$id] } else { $null }
    }
}

# ----------------------------------------
# Append current run to CSV log
# ----------------------------------------
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$csvRows = foreach ($row in $Table) {
    [PSCustomObject]@{
        Timestamp   = $timestamp
        DiskNumber  = $DiskNumber
        AttributeID = $row.AttributeID
        RawValue    = $row.RawValue
        Attribute   = $row.Attribute
    }
}
$csvRows | Export-Csv -Path $CsvFile -Append -NoTypeInformation -Encoding UTF8

Write-Log "SMART data logged to CSV: $CsvFile"

# ----------------------------------------
# Analyze status (threshold-based)
# ----------------------------------------
$Degraded = @()
$Failing = @()

foreach ($id in $SmartAttributes.Keys) {
    $value = $CurrentValues[$id]
    if ($null -eq $value) { continue }

    switch ($id) {
        5   { if ($value -gt 0 -and $value -lt 10) { $Degraded += $id }; if ($value -ge 10) { $Failing += $id } }
        187 { if ($value -gt 0) { $Failing += $id } }
        197 { if ($value -gt 0 -and $value -lt 5) { $Degraded += $id }; if ($value -ge 5) { $Failing += $id } }
        198 { if ($value -gt 0) { $Failing += $id } }
        1   { if ($Previous.ContainsKey($id) -and $Previous[$id] -ne $null -and ($value - $Previous[$id]) -gt 100) { $Degraded += $id } }
        7   { if ($value -gt 100) { $Degraded += $id } }
        10  { if ($value -gt 0) { $Failing += $id } }
        184 { if ($value -gt 0) { $Failing += $id } }
        188 { if ($value -gt 100) { $Degraded += $id } }
        193 { if ($value -gt 600000) { $Degraded += $id } }
        194 { if ($value -gt 55 -and $value -lt 70) { $Degraded += $id }; if ($value -ge 70) { $Failing += $id } }
        196 { if ($value -gt 0) { $Degraded += $id } }
        199 { if ($value -gt 50) { $Degraded += $id } }
        231 { if ($value -ge 80 -and $value -lt 95) { $Degraded += $id }; if ($value -ge 95) { $Failing += $id } }
    }
}

# ----------------------------------------
# Analyze changes (delta-based)
# ----------------------------------------
$ChangedWarnings = @()

$ChangeThresholds = @{
    5   = 1    # Any new reallocated sectors
    187 = 1    # Any new uncorrectable errors
    196 = 1    # Any new reallocation events
    197 = 1    # Any new pending sectors
    198 = 1    # Any new uncorrectable sectors
    10  = 1    # Any new spin retries
    184 = 1    # Any new end-to-end errors
    199 = 10   # CRC errors - small threshold
    188 = 20   # Command timeouts - occasional is OK
    231 = 5    # NVMe % used jumped 5+ between checks
}

foreach ($id in $ChangeThresholds.Keys) {
    if (-not $Previous.ContainsKey($id) -or $null -eq $Previous[$id] -or $null -eq $CurrentValues[$id]) { continue }

    $delta = $CurrentValues[$id] - $Previous[$id]
    if ($delta -ge $ChangeThresholds[$id]) {
        $ChangedWarnings += [PSCustomObject]@{
            AttributeID = $id
            Attribute   = $SmartAttributes[$id].Name
            Previous    = $Previous[$id]
            Current     = $CurrentValues[$id]
            Delta       = $delta
        }
        Write-Log "CHANGE DETECTED: $($SmartAttributes[$id].Name) increased by $delta ($($Previous[$id]) -> $($CurrentValues[$id]))" -Level WARN

        if ($id -notin $Degraded -and $id -notin $Failing) {
            $Degraded += $id
        }
    }
}

# ----------------------------------------
# Final diagnosis
# ----------------------------------------
$Status = "OK"
$ExitCode = 0
$Explanation = ""

if ($Failing.Count -gt 0) {
    $Status = "FAILING"
    $ExitCode = 2
    $Explanation = "These attributes indicate physical drive failure: " +
        (($Failing | ForEach-Object { "$_ ($($SmartAttributes[$_].Name))" }) -join ", ")
    Write-Log "Disk health status: FAILING - $Explanation" -Level ERROR
}
elseif ($Degraded.Count -gt 0) {
    $Status = "DEGRADED"
    $ExitCode = 1
    $Explanation = "These attributes show early signs of deterioration: " +
        (($Degraded | ForEach-Object { "$_ ($($SmartAttributes[$_].Name))" }) -join ", ")
    Write-Log "Disk health status: DEGRADED - $Explanation" -Level WARN
}
else {
    $Explanation = "No SMART attributes show signs of physical damage."
    Write-Log "Disk health status: OK - $Explanation"
}

if ($ChangedWarnings.Count -gt 0) {
    $changeDetail = ($ChangedWarnings | ForEach-Object { "$($_.Attribute): $($_.Previous)->$($_.Current) (+$($_.Delta))" }) -join "; "
    $Explanation += " [CHANGES SINCE LAST RUN: $changeDetail]"
}

# ----------------------------------------
# Build summary string
# ----------------------------------------
$driveModel = if ($SmartData.model_name) { $SmartData.model_name } else { "Unknown" }
$temp = if ($null -ne $CurrentValues[194]) { "$($CurrentValues[194])C" } else { "N/A" }
$nvmeLife = if ($null -ne $CurrentValues[231]) { " | Life: $($CurrentValues[231])%" } else { "" }
$changeCount = if ($ChangedWarnings.Count -gt 0) { " | $($ChangedWarnings.Count) changed" } else { "" }
$Summary = "$Status | $driveModel | $temp$nvmeLife$changeCount"

# ----------------------------------------
# Output final result
# ----------------------------------------
Write-Host ""
Write-Host "========== SMART SUMMARY (OS Disk) =========="
Write-Host ""
Write-Host "Disk Number:  $DiskNumber"
Write-Host "Status:       $Status"
Write-Host "Summary:      $Summary"
Write-Host "Explanation:  $Explanation"
Write-Host ""

if ($ChangedWarnings.Count -gt 0) {
    Write-Host "========== Changes Since Last Run ==========" -ForegroundColor Yellow
    $ChangedWarnings | Format-Table -AutoSize
}

Write-Host "========== Attribute Table =========="
$Table | Format-Table -AutoSize

Write-Log "Disk health check completed: $Status"
exit $ExitCode
