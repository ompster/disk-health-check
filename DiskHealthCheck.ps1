#
# SMART Disk Health Check Script
# Uses smartctl (smartmontools) for full raw SMART attribute data
# Auto-installs smartmontools if not present on the system
# Supports Datto RMM (CentraStage UDF writes, component exit codes)
# Also works standalone from any PowerShell administrator session
#

#region ========================= TOOLKIT FUNCTIONS =========================
# Only including functions actually used by this script

# Global log path - Datto components run from a temp dir, so we log to a known location
$script:LogPath = "$env:ProgramData\CentraStage\Logs\component-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Message,

        [ValidateSet('INFO', 'WARN', 'ERROR', 'DEBUG')]
        [string]$Level = 'INFO',

        [string]$LogFile = $script:LogPath
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry = "[$timestamp] [$Level] $Message"

    # Ensure log directory exists
    $logDir = Split-Path $LogFile -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }

    # Write to file
    Add-Content -Path $LogFile -Value $entry -Encoding UTF8

    # Write to stdout/stderr (Datto captures this in component output)
    switch ($Level) {
        'ERROR' { Write-Error $Message }
        'WARN' { Write-Warning $Message }
        'DEBUG' { Write-Verbose $Message -Verbose }
        default { Write-Output $entry }
    }
}

function Exit-Component {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$ExitCode,

        [Parameter(Mandatory)]
        [string]$Message
    )

    $level = if ($ExitCode -eq 0) { 'INFO' } else { 'ERROR' }
    Write-Log $Message -Level $level
    Write-Log "Exiting with code: $ExitCode"

    # When running in VS Code or ISE, avoid `exit` as it kills the terminal.
    # In those hosts, throw an exception so the output remains visible.
    $hostName = $Host.Name
    if ($hostName -match 'Visual Studio Code|ISE') {
        if ($ExitCode -ne 0) {
            throw "[Exit $ExitCode] $Message"
        }
        return
    }

    # In non-interactive / Datto RMM context, use real exit codes
    [Console]::Out.Flush()
    exit $ExitCode
}

function Exit-Success { 
    param([string]$Message = 'Component completed successfully.')
    Exit-Component -ExitCode 0 -Message $Message 
}

function Exit-Failure { 
    param([string]$Message = 'Component failed.', [int]$ExitCode = 1)
    Exit-Component -ExitCode $ExitCode -Message $Message 
}
#endregion

# ===========================
# SMART Monitoring Script (OS Drive Only)
# Logs + Compares Previous Run
# ===========================

# ----------------------------------------
# Configuration
# ----------------------------------------
# UDF number to write status summary to (Datto RMM custom field)
# Override via Datto component variable or environment variable
$UdfNumber = if ($env:UdfNumber) { [int]$env:UdfNumber } else { 8 }

# CSV log path - override via $env:CsvLogPath or defaults to ProgramData
$CsvLogPath = if ($env:CsvLogPath) { $env:CsvLogPath } else { "$env:ProgramData\DiskHealthCheck\log" }

# ----------------------------------------
# Require Administrator privileges
# ----------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) {
    Write-Host 'ERROR: This script must be run as Administrator. Right-click PowerShell / VS Code and select "Run as administrator".' -ForegroundColor Red
    return
}

$CsvFile = Join-Path $CsvLogPath "SMART_Report.csv"
if (!(Test-Path $CsvLogPath)) { New-Item -ItemType Directory -Path $CsvLogPath -Force | Out-Null }

Write-Log "Starting SMART disk health check for OS drive"

# ----------------------------------------
# SMART ATTRIBUTES OF INTEREST
# ----------------------------------------
$SmartAttributes = @{
    1   = @{ Name = "Read Error Rate"; Meaning = "High values indicate the drive is struggling to read data; early physical failure." }
    5   = @{ Name = "Reallocated Sectors"; Meaning = "Bad sectors that have been replaced; any non-zero value is a warning." }
    7   = @{ Name = "Seek Error Rate"; Meaning = "Head positioning errors; mechanical degradation." }
    10  = @{ Name = "Spin Retry Count"; Meaning = "Drive motor struggled to spin; motor failure risk." }
    184 = @{ Name = "End-to-End Error"; Meaning = "Data corruption detected internally; controller failure." }
    187 = @{ Name = "Reported Uncorrectable Errors"; Meaning = "Errors the drive could not correct; physical media failure." }
    188 = @{ Name = "Command Timeout"; Meaning = "Drive became unresponsive or stalled." }
    193 = @{ Name = "Load Cycle Count"; Meaning = "High values can indicate excessive head parking (>600,000 is concerning)." }
    196 = @{ Name = "Reallocation Events"; Meaning = "Count of reallocation attempts; indicators of growing surface damage." }
    197 = @{ Name = "Current Pending Sector"; Meaning = "Sectors waiting for reallocation; physical damage likely." }
    198 = @{ Name = "Uncorrectable Sector Count"; Meaning = "Permanent data loss in sectors; severe deterioration." }
    199 = @{ Name = "UDMA CRC Error Count"; Meaning = "Cable/connection issues (not physical damage but relevant)." }
    194 = @{ Name = "Temperature"; Meaning = "Drive operating temperature in Celsius." }
    231 = @{ Name = "SSD Life Left / NVMe % Used"; Meaning = "Percentage of rated lifetime consumed. 100 = end of rated life." }
}

# ----------------------------------------
# Helper: Get OS Disk Number
# ----------------------------------------
$osVolume = Get-Partition -DriveLetter C | Get-Disk
$DiskNumber = $osVolume.Number
Write-Log "OS disk identified as Disk Number: $DiskNumber"

# ----------------------------------------
# Helper: Find or Install smartctl
# ----------------------------------------
function Get-SmartctlPath {
    # Check common install locations
    $searchPaths = @(
        "C:\Program Files\smartmontools\bin\smartctl.exe",
        "C:\Program Files (x86)\smartmontools\bin\smartctl.exe"
    )

    foreach ($p in $searchPaths) {
        if (Test-Path $p) { return $p }
    }

    # Check PATH
    $inPath = Get-Command smartctl.exe -ErrorAction SilentlyContinue
    if ($inPath) { return $inPath.Source }

    return $null
}

function Install-Smartmontools {
    # IMPORTANT: All Write-Log calls piped to Out-Null to prevent stdout pollution.
    # PowerShell captures ALL stdout from a function as its return value.
    # Without Out-Null, the returned path would contain log lines mixed in.
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

        # Clean up installer
        Remove-Item $installerPath -Force -ErrorAction SilentlyContinue

        # Verify installation
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
        # Clean up on failure
        Remove-Item $installerPath -Force -ErrorAction SilentlyContinue
        return $null
    }
}

# ----------------------------------------
# Find or install smartctl
# ----------------------------------------
$SmartctlExe = Get-SmartctlPath
if (-not $SmartctlExe) {
    $SmartctlExe = Install-Smartmontools
}

if (-not $SmartctlExe) {
    Exit-Failure "smartmontools could not be found or installed. Cannot retrieve SMART data." -ExitCode 2
}

Write-Log "Using smartctl: $SmartctlExe"

# ----------------------------------------
# Get SMART data via smartctl JSON
# ----------------------------------------
# Use --scan to discover the correct device path and type (nvme, sat, etc.)
# smartctl on Windows works best with its own /dev/sdX paths rather than \\.\PhysicalDriveN
$DevicePath = "\\.\PhysicalDrive$DiskNumber"
$DeviceType = $null
try {
    $scanOutput = & $SmartctlExe --scan 2>&1
    # --scan output lines look like: /dev/sda -d nvme # /dev/sda, NVMe device
    # PhysicalDrive0 = /dev/sda, PhysicalDrive1 = /dev/sdb, etc.
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

    # smartctl may return non-zero exit codes with bit flags even on success
    # Bit 0 = command line parse error, Bit 1 = device open failed - these are fatal
    # Other bits are informational (e.g. bit 5 = some attributes past threshold)
    if ($LASTEXITCODE -band 3) {
        throw "smartctl returned fatal error (exit code $LASTEXITCODE): $($jsonRaw -join "`n")"
    }

    $jsonString = $jsonRaw -join "`n"
    $SmartData = $jsonString | ConvertFrom-Json
}
catch {
    Write-Log "Failed to run smartctl: $_" -Level ERROR
    Exit-Failure "Failed to retrieve SMART data via smartctl: $_" -ExitCode 2
}

# ----------------------------------------
# Parse SMART attributes from JSON
# ----------------------------------------
$CurrentValues = @{}

# Check if this is an ATA drive with classic SMART attributes
if ($SmartData.ata_smart_attributes -and $SmartData.ata_smart_attributes.table) {
    Write-Log "Drive reports ATA SMART attributes"
    foreach ($attr in $SmartData.ata_smart_attributes.table) {
        $attrId = [int]$attr.id
        if ($SmartAttributes.ContainsKey($attrId)) {
            $CurrentValues[$attrId] = [long]$attr.raw.value
        }
    }
}
# NVMe drives report health differently
elseif ($SmartData.nvme_smart_health_information_log) {
    Write-Log "Drive reports NVMe health information"
    $nvme = $SmartData.nvme_smart_health_information_log

    # Map NVMe fields to our attribute IDs where conceptually equivalent
    $CurrentValues[194] = $(
        if ($nvme.temperature -is [int]) { $nvme.temperature }
        elseif ($nvme.temperature_sensors) { $nvme.temperature_sensors[0] }
        else { $null }
    )
    $CurrentValues[187] = $nvme.media_errors          # Media/data integrity errors
    $CurrentValues[1] = $nvme.num_err_log_entries   # Error log entries (closest to read errors)
    $CurrentValues[231] = $nvme.percentage_used      # NVMe lifetime used (100 = rated end of life)
}
else {
    Write-Log "No recognisable SMART attribute data found in smartctl output" -Level WARN
}

# Fill in any missing attributes with $null so the table is consistent
foreach ($id in $SmartAttributes.Keys) {
    if (-not $CurrentValues.ContainsKey($id)) {
        $CurrentValues[$id] = $null
    }
}

# Log drive info
if ($SmartData.model_name) {
    Write-Log "Drive model: $($SmartData.model_name)"
}
if ($SmartData.serial_number) {
    Write-Log "Drive serial: $($SmartData.serial_number)"
}

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
# Append current run to CSV using Export-Csv for proper escaping
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

    # Skip attributes not reported by this drive
    if ($null -eq $value) { continue }

    switch ($id) {
        5   { if ($value -gt 0 -and $value -lt 10) { $Degraded += $id }; if ($value -ge 10) { $Failing += $id } }
        187 { if ($value -gt 0) { $Failing += $id } }
        197 { if ($value -gt 0 -and $value -lt 5) { $Degraded += $id }; if ($value -ge 5) { $Failing += $id } }
        198 { if ($value -gt 0) { $Failing += $id } }
        1   { # Read Error Rate - some drives (Seagate) report huge normalized values as normal.
              # Only flag if previous run exists and value has increased significantly.
              if ($Previous.ContainsKey($id) -and $Previous[$id] -ne $null -and ($value - $Previous[$id]) -gt 100) { $Degraded += $id }
            }
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
# These attributes are concerning if they INCREASE between runs, regardless of absolute value.
# A jump means active degradation is happening right now.
$ChangedWarnings = @()

$ChangeThresholds = @{
    5   = 1    # Any new reallocated sectors
    187 = 1    # Any new uncorrectable errors
    196 = 1    # Any new reallocation events
    197 = 1    # Any new pending sectors
    198 = 1    # Any new uncorrectable sectors
    10  = 1    # Any new spin retries
    184 = 1    # Any new end-to-end errors
    199 = 10   # CRC errors can be cabling - small threshold
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

        # Promote to at least Degraded if not already flagged
        if ($id -notin $Degraded -and $id -notin $Failing) {
            $Degraded += $id
        }
    }
}

# ----------------------------------------
# Final diagnosis
# ----------------------------------------
$Status = "OK"
$Exit = 0
$Explanation = ""

if ($Failing.Count -gt 0) {
    $Status = "FAILING"
    $Exit = 2
    $Explanation = "These attributes indicate physical drive failure: " +
    (($Failing | ForEach-Object { "$_ ($($SmartAttributes[$_].Name))" }) -join ", ")
    Write-Log "Disk health status: FAILING - $Explanation" -Level ERROR
}
elseif ($Degraded.Count -gt 0) {
    $Status = "DEGRADED"
    $Exit = 1
    $Explanation = "These attributes show early signs of deterioration: " +
    (($Degraded | ForEach-Object { "$_ ($($SmartAttributes[$_].Name))" }) -join ", ")
    Write-Log "Disk health status: DEGRADED - $Explanation" -Level WARN
}
else {
    $Explanation = "No SMART attributes show signs of physical damage."
    Write-Log "Disk health status: OK - $Explanation"
}

# Add change warnings to explanation if any
if ($ChangedWarnings.Count -gt 0) {
    $changeDetail = ($ChangedWarnings | ForEach-Object { "$($_.Attribute): $($_.Previous)->$($_.Current) (+$($_.Delta))" }) -join "; "
    $Explanation += " [CHANGES SINCE LAST RUN: $changeDetail]"
}

# ----------------------------------------
# Build UDF string and write to Datto RMM
# ----------------------------------------
$driveModel = if ($SmartData.model_name) { $SmartData.model_name } else { "Unknown" }
$temp = if ($null -ne $CurrentValues[194]) { "$($CurrentValues[194])C" } else { "N/A" }
$nvmeLife = if ($null -ne $CurrentValues[231]) { " | Life: $($CurrentValues[231])%" } else { "" }
$changeCount = if ($ChangedWarnings.Count -gt 0) { " | $($ChangedWarnings.Count) changed" } else { "" }

# UDF format: "OK | Samsung SSD 980 | 42C | Life: 3%" or "DEGRADED | WDC WD10 | 55C | 2 changed"
$UdfValue = "$Status | $driveModel | $temp$nvmeLife$changeCount"

# Truncate to 255 chars (Datto UDF limit)
if ($UdfValue.Length -gt 255) { $UdfValue = $UdfValue.Substring(0, 252) + "..." }

Write-Log "Writing to UDF $UdfNumber`: $UdfValue"

# Write to Datto UDF via registry (only works in Datto RMM context)
$udfRegPath = "HKLM:\SOFTWARE\CentraStage"
if (Test-Path $udfRegPath) {
    try {
        Set-ItemProperty -Path $udfRegPath -Name "Custom$UdfNumber" -Value $UdfValue -ErrorAction Stop
        Write-Log "UDF $UdfNumber written successfully"
    }
    catch {
        Write-Log "Failed to write UDF $UdfNumber`: $_" -Level WARN
    }
}
else {
    Write-Log "Datto RMM registry path not found - skipping UDF write (not running in Datto context)" -Level WARN
}

# ----------------------------------------
# Output final result
# ----------------------------------------
Write-Host ""
Write-Host "========== SMART SUMMARY (OS Disk Only) =========="
Write-Host ""
Write-Host "Disk Number: $DiskNumber"
Write-Host "Status: $Status"
Write-Host "Explanation: $Explanation"
Write-Host "UDF $UdfNumber`: $UdfValue"
Write-Host ""

if ($ChangedWarnings.Count -gt 0) {
    Write-Host "========== Changes Since Last Run ==========" -ForegroundColor Yellow
    $ChangedWarnings | Format-Table -AutoSize
}

Write-Host "========== Attribute Table =========="
$Table | Format-Table -AutoSize

# Exit with semantic meaning preserved
if ($Exit -eq 0) {
    Exit-Success "Disk health check completed: $Status - $Explanation"
}
elseif ($Exit -eq 1) {
    Exit-Failure "Disk health degraded: $Explanation" -ExitCode 1
}
else {
    Exit-Failure "Disk failing: $Explanation" -ExitCode 2
}
