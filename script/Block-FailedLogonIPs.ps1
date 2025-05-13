<# 
    Script: Block-FailedLogonIPs.ps1
    Purpose: Monitors Event ID 4625 for failed logon attempts. Using Windows firewall, auto blocks 
             non-US IPs on first attempt and blocks US IPs with more than 5 attempts in 10 minutes. 
             Checks for existing Windows firewall rules before querying IP geolocation API, using 
             batch queries for 2+ IPs (15 req/min) and single queries for 1 IP (45 req/min). 
             Manages separate rate limits via limits file and response headers (X-Rl, X-Ttl). 
             Logs new blocks, existing rules, and errors to C:\BlockIPScript\Logs\BlockIP.log.
    Author: Nicholas Carter (SiY11@hotmail.com)
    Date: May 2025
    Notes:
    - Runs via Task Scheduler when event ID 4625 triggers, you need to create this task with admin rights.
    - I suggest creating a local service account with admin rights to be used for running this task.
    - Appends to a single log file C:\BlockIPScript\Logs\BlockIP.log.
    - Logs only new firewall rules, existing rules, or errors.
    - Uses ip-api.com for IP geolocation (free, 45 req/min for single, 15 req/min for batch).
    - Tracks rate limits in C:\BlockIPScript\Logs\IPAPILimits.json.
#>

# ----- Parameters for Dynamic Thresholds -----
param (
    [Parameter(Mandatory = $false)]
    [int]$AttemptThreshold = 5,  # Default: 5 attempts for US IPs

    [Parameter(Mandatory = $false)]
    [int]$TimeWindowMinutes = 10  # Default: 10-minute window
)

# ----- Configuration -----
#region Configuration
# Define log and limits file paths
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path  # Fallback for older PowerShell versions
if ($PSCommandPath) { $ScriptRoot = Split-Path -Parent $PSCommandPath }  # Use PSCommandPath if available
$LogDir = Join-Path (Split-Path -Parent $ScriptRoot) "Logs"  # e.g., C:\BlockIPScript\Logs
if (-not (Test-Path -Path $LogDir)) {
    New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
}
$LogFile = Join-Path $LogDir "BlockIP.log"
$LimitsFile = Join-Path $LogDir "IPAPILimits.json"

# Log rotation settings
$MaxLogSizeMB = 10  # Maximum size of BlockIP.log in MB
$LogRetentionDays = 365  # Days to retain archived logs (if not unlimited)
$LogRetentionUnlimited = $true  # Set to $true to keep archives indefinitely
$LimitsBackupRetentionDays = 1  # Days to retain limits file backups

# Ensure log directory exists
if (-not (Test-Path $LogDir)) {
    try {
        New-Item -ItemType Directory -Path $LogDir -Force -ErrorAction Stop | Out-Null
    } catch {
        Write-Error "Failed to create log directory: $($_.Exception.Message)"
        exit
    }
}

# Function to write to log file
function Write-Log {
    param (
        [string]$Level,
        [string]$Message
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] $Level : $Message"
    try {
        Add-Content -Path $LogFile -Value $LogEntry -ErrorAction Stop
    } catch {
        Write-Error "Failed to write to log file: $($_.Exception.Message)"
    }
}

# Function to rotate log file
function Rotate-LogFile {
    try {
        $LogSizeMB = (Get-Item $LogFile -ErrorAction SilentlyContinue).Length / 1MB
        if ($LogSizeMB -ge $MaxLogSizeMB) {
            $ArchiveName = "BlockIP_$(Get-Date -Format 'yyyyMMdd').log"
            $ArchivePath = Join-Path $LogDir $ArchiveName
            Move-Item -Path $LogFile -Destination $ArchivePath -Force -ErrorAction Stop
            Compress-Archive -Path $ArchivePath -DestinationPath "$ArchivePath.zip" -Force -ErrorAction Stop
            Remove-Item -Path $ArchivePath -ErrorAction Stop

            # Delete old archives (unless unlimited retention)
            if (-not $LogRetentionUnlimited) {
                $CutoffDate = (Get-Date).AddDays(-$LogRetentionDays)
                Get-ChildItem -Path $LogDir -Filter "BlockIP_*.log.zip" | Where-Object {
                    $_.CreationTime -lt $CutoffDate
                } | Remove-Item -Force -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-Log -Level "ERROR" -Message "Failed to rotate log file: $($_.Exception.Message)"
    }
}

# Function to backup limits file
function Backup-LimitsFile {
    try {
        if (Test-Path $LimitsFile) {
            $BackupName = "IPAPILimits_$(Get-Date -Format 'yyyyMMdd').json"
            $BackupPath = Join-Path $LogDir $BackupName
            Copy-Item -Path $LimitsFile -Destination $BackupPath -Force -ErrorAction Stop

            # Delete old backups
            $CutoffDate = (Get-Date).AddDays(-$LimitsBackupRetentionDays)
            Get-ChildItem -Path $LogDir -Filter "IPAPILimits_*.json" | Where-Object {
                $_.CreationTime -lt $CutoffDate
            } | Remove-Item -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Log -Level "ERROR" -Message "Failed to backup limits file: $($_.Exception.Message)"
    }
}

# Perform log rotation and limits file backup at script start
Rotate-LogFile
Backup-LimitsFile

# Function to manage rate limits
function Get-RateLimitStatus {
    param (
        [string]$Type  # "Single" or "Batch"
    )
    $DefaultLimits = @{
        Single = @{ RemainingRequests = 45; ResetTime = (Get-Date).ToUniversalTime().ToString("o") }
        Batch  = @{ RemainingRequests = 15; ResetTime = (Get-Date).ToUniversalTime().ToString("o") }
    }

    # Load limits file or initialize
    $Limits = if (Test-Path $LimitsFile) {
        Get-Content $LimitsFile -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
    } else {
        $DefaultLimits
    }
    if (-not $Limits) { $Limits = $DefaultLimits }

    # Check if rate limit is exhausted
    $Limit = $Limits.$Type
    $ResetTime = [DateTime]::Parse($Limit.ResetTime, $null, [System.Globalization.DateTimeStyles]::RoundtripKind)
    $Now = (Get-Date).ToUniversalTime()

    if ($Limit.RemainingRequests -le 0 -and $Now -lt $ResetTime) {
        $WaitSeconds = [math]::Ceiling(($ResetTime - $Now).TotalSeconds)
        Write-Log -Level "INFO" -Message "Rate limit exhausted for $Type API. Waiting $WaitSeconds seconds."
        Start-Sleep -Seconds $WaitSeconds
        # Reset limits after waiting
        $Limit.RemainingRequests = if ($Type -eq "Single") { 45 } else { 15 }
        $Limit.ResetTime = (Get-Date).AddMinutes(1).ToUniversalTime().ToString("o")
        $Limits | ConvertTo-Json | Set-Content $LimitsFile -ErrorAction SilentlyContinue
    }

    return $Limit
}

# Function to update rate limits from response headers
function Update-RateLimit {
    param (
        [string]$Type,
        [object]$Response
    )
    $Limits = if (Test-Path $LimitsFile) {
        Get-Content $LimitsFile -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
    } else {
        @{
            Single = @{ RemainingRequests = 45; ResetTime = (Get-Date).ToUniversalTime().ToString("o") }
            Batch  = @{ RemainingRequests = 15; ResetTime = (Get-Date).ToUniversalTime().ToString("o") }
        }
    }

    $Headers = $Response.Headers
    $Remaining = if ($Headers["X-Rl"]) { [int]$Headers["X-Rl"] } else { $Limits.$Type.RemainingRequests }
    $Ttl = if ($Headers["X-Ttl"]) { [int]$Headers["X-Ttl"] } else { 60 }

    $Limits.$Type.RemainingRequests = $Remaining
    $Limits.$Type.ResetTime = (Get-Date).AddSeconds($Ttl).ToUniversalTime().ToString("o")
    $Limits | ConvertTo-Json | Set-Content $LimitsFile -ErrorAction SilentlyContinue
}

# Define time window
$TimeWindow = (Get-Date).AddMinutes(-$TimeWindowMinutes)

# Define private IP ranges to exclude
$PrivateIPRanges = @(
    '^192\.168\.',
    '^10\.',
    '^172\.(1[6-9]|2[0-9]|3[0-1])\.'
)

# Function to validate IPv4 address
function Test-IPv4Address {
    param (
        [string]$IP
    )
    $IPv4Regex = '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    return $IP -match $IPv4Regex
}

# Function to get country code and name (single IP)
function Get-CountryCode {
    param (
        [string]$IP
    )
    try {
        # Check rate limit
        $Limit = Get-RateLimitStatus -Type "Single"
        if ($Limit.RemainingRequests -le 0) { return $null, $null }

        $Uri = "http://ip-api.com/json/$IP"
        $Response = Invoke-WebRequest -Uri $Uri -Method Get -UseBasicParsing -ErrorAction Stop
        Update-RateLimit -Type "Single" -Response $Response

        $Data = $Response.Content | ConvertFrom-Json
        if ($Data.status -eq "success") {
            return $Data.countryCode, $Data.country
        } else {
            throw "API returned failure status: $($Data.message)"
        }
    } catch {
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode -eq 429) {
            Write-Log -Level "ERROR" -Message "Rate limit exceeded for IP $IP - retrying after checking limits"
            Update-RateLimit -Type "Single" -Response $_.Exception.Response
            return Get-CountryCode -IP $IP
        }
        Write-Log -Level "ERROR" -Message "Failed to get country for IP $IP - $($_.Exception.Message)"
        return $null, $null
    }
}

# Function to get country codes and names (batch IPs)
function Get-CountryCodesBatch {
    param (
        [string[]]$IPs
    )
    try {
        # Check rate limit
        $Limit = Get-RateLimitStatus -Type "Batch"
        if ($Limit.RemainingRequests -le 0) { 
            $Results = @{}
            foreach ($IP in $IPs) { $Results[$IP] = $null, $null }
            return $Results
        }

        # Ensure no more than 100 IPs
        if ($IPs.Count -gt 100) {
            Write-Log -Level "ERROR" -Message "Batch query exceeds 100 IPs (requested: $($IPs.Count))"
            $Results = @{}
            foreach ($IP in $IPs) { $Results[$IP] = $null, $null }
            return $Results
        }

        $Uri = "http://ip-api.com/batch"
        $Body = ConvertTo-Json $IPs -Compress
        $Response = Invoke-WebRequest -Uri $Uri -Method Post -Body $Body -ContentType "application/json" -UseBasicParsing -ErrorAction Stop
        Update-RateLimit -Type "Batch" -Response $Response

        $Results = @{}
        foreach ($Result in ($Response.Content | ConvertFrom-Json)) {
            if ($Result.status -eq "success") {
                $Results[$Result.query] = $Result.countryCode, $Result.country
            } else {
                Write-Log -Level "ERROR" -Message "Failed to get country for IP $($Result.query) - $($Result.message)"
                $Results[$Result.query] = $null, $null
            }
        }
        return $Results
    } catch {
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode -eq 429) {
            Write-Log -Level "ERROR" -Message "Rate limit exceeded for batch query - retrying after checking limits"
            Update-RateLimit -Type "Batch" -Response $_.Exception.Response
            return Get-CountryCodesBatch -IPs $IPs
        } elseif ($_.Exception.Response -and $_.Exception.Response.StatusCode -eq 422) {
            Write-Log -Level "ERROR" -Message "Batch query invalid (possibly >100 IPs) - $($_.Exception.Message)"
            $Results = @{}
            foreach ($IP in $IPs) { $Results[$IP] = $null, $null }
            return $Results
        }
        Write-Log -Level "ERROR" -Message "Failed batch query for IPs $($IPs -join ', ') - $($_.Exception.Message)"
        $Results = @{}
        foreach ($IP in $IPs) { $Results[$IP] = $null, $null }
        return $Results
    }
}

# Get Event ID 4625 from Security log
try {
    $Events = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4625
        StartTime = $TimeWindow
    } -ErrorAction Stop
} catch {
    Write-Log -Level "ERROR" -Message "Failed to retrieve events: $($_.Exception.Message)"
    exit
}

# Dictionary to store IP counts and HashSet for unique IPs
$IPCounts = @{}
$UniqueIPs = New-Object System.Collections.Generic.HashSet[string]
#endregion Configuration

# ----- Main Logic -----
#region MainLogic
# Process each event to count IPs and collect unique IPs
foreach ($Event in $Events) {
    try {
        # Parse event XML to get Source Network Address
        $EventXML = [xml]$Event.ToXml()
        $SourceIP = $EventXML.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' } | Select-Object -ExpandProperty '#text'

        # Skip if no IP, invalid IP, or not IPv4
        if (-not $SourceIP -or $SourceIP -eq '-' -or -not (Test-IPv4Address -IP $SourceIP)) { continue }

        # Check if IP is private
        $IsPrivate = $false
        foreach ($Range in $PrivateIPRanges) {
            if ($SourceIP -match $Range) {
                $IsPrivate = $true
                break
            }
        }

        # Skip private IPs
        if ($IsPrivate) { continue }

        # Increment IP count and add to unique IPs
        if ($IPCounts.ContainsKey($SourceIP)) {
            $IPCounts[$SourceIP]++
        } else {
            $IPCounts[$SourceIP] = 1
        }
        $UniqueIPs.Add($SourceIP) | Out-Null
    } catch {
        Write-Log -Level "ERROR" -Message "Error processing event: $($_.Exception.Message)"
    }
}

# Filter IPs that don't have existing firewall rules
$IPsToQuery = New-Object System.Collections.Generic.List[string]
foreach ($IP in $UniqueIPs) {
    try {
        $RuleName = "Block_IP_$IP"
        $ExistingRule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue

        if ($ExistingRule) {
            # Log existing rule and skip API call
            Write-Log -Level "INFO" -Message "Rule already exists for IP: $IP"
            Write-Output "Rule already exists for IP: $IP"
            continue
        }

        $IPsToQuery.Add($IP)
    } catch {
        Write-Log -Level "ERROR" -Message "Error checking firewall rule for IP $IP - $($_.Exception.Message)"
    }
}

# Query geolocation for IPs
$CountryData = @{}
if ($IPsToQuery.Count -ge 2) {
    # Use batch query for 2+ IPs (up to 100 at a time)
    $BatchSize = 100
    for ($i = 0; $i -lt $IPsToQuery.Count; $i += $BatchSize) {
        $BatchIPs = $IPsToQuery.GetRange($i, [Math]::Min($BatchSize, $IPsToQuery.Count - $i))
        $BatchResults = Get-CountryCodesBatch -IPs $BatchIPs
        $CountryData += $BatchResults
    }
} elseif ($IPsToQuery.Count -eq 1) {
    # Use single query for one IP
    $IP = $IPsToQuery[0]
    $CountryCode, $Country = Get-CountryCode -IP $IP
    $CountryData[$IP] = $CountryCode, $Country
}

# Process IPs for blocking
foreach ($IP in $IPsToQuery) {
    try {
        $CountryCode, $Country = $CountryData[$IP]
        if (-not $CountryCode) { continue }  # Skip if country couldn't be determined
		
		$WhitelistPath = Join-Path (Split-Path -Parent $ScriptRoot) "allowed_ips.txt"
		$Whitelist = if (Test-Path $WhitelistPath) { Get-Content -Path $WhitelistPath | Where-Object { $_ -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$' } } else { @() }
		if ($Whitelist -contains $IP) {
			Write-Log -Level "INFO" -Message "IP $IP is in allowed_ips.txt, skipping block."
			continue
		}
		
        # Determine if IP should be blocked
        $ShouldBlock = $false
        $Reason = ""
        if ($CountryCode -ne "US") {
            # Non-US IPs: block on first attempt
            $ShouldBlock = $true
            $Reason = "IP is outside the USA (country: $Country)"
        } elseif ($CountryCode -eq "US" -and $IPCounts[$IP] -gt $AttemptThreshold) {
            # US IPs: block if >$AttemptThreshold attempts
            $ShouldBlock = $true
            $Reason = "IP in USA with >$AttemptThreshold attempts (attempts: $($IPCounts[$IP]))"
        }

        # Block IP if conditions met
        if ($ShouldBlock) {
            $RuleName = "Block_IP_$IP"
            # Log IP violation
            Write-Log -Level "INFO" -Message "IP $IP found in violation ($Reason)"

            # Create inbound firewall rule to block IP
            New-NetFirewallRule -DisplayName $RuleName `
                -Direction Inbound `
                -Action Block `
                -RemoteAddress $IP `
                -Protocol Any `
                -Profile Any `
                -Description "Auto-blocked due to $Reason" -ErrorAction Stop

            Write-Log -Level "INFO" -Message """$RuleName"" rule created in Windows firewall"
            Write-Output "Blocked IP: $IP ($Reason)"
        }
    } catch {
        Write-Log -Level "ERROR" -Message "Error processing IP $IP - $($_.Exception.Message)"
    }
}
#endregion MainLogic