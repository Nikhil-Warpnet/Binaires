#Requires -Version 5.1
<#
.SYNOPSIS
    Subnet scanner for ports 80/443 with HTTP fingerprinting and title extraction.

.DESCRIPTION
    Scans one or more subnets for hosts with open ports 80 and/or 443.
    For each responsive host it collects:
      - Open ports
      - HTTP page title
      - Server header
      - X-Powered-By header
      - Content-Type
      - Redirect target (if any)
      - TLS certificate CN (port 443)
    Results are written to a timestamped JSON file AND a human-readable TXT report.

.NOTES
    Edit the $Subnets array below to add/remove target subnets.
    Requires PowerShell 5.1+ (Windows) or PowerShell 7+ (cross-platform).
#>

# =============================================================================
#  CONFIGURATION  –  hardcode your subnets here (CIDR /8 through /30 supported)
# =============================================================================
$Subnets = @(
    "10.2.0.0/24",
    "10.2.7.0/24",
    "10.1.176.0/24",
    "10.1.178.0/24"
    # Add more as needed, e.g.:  "172.16.5.0/27"
)

$PortsToScan      = @(80, 443)
$ConnectTimeoutMs = 800        # TCP connect timeout per host/port (ms)
$HttpTimeoutSec   = 5          # HTTP(S) request timeout (seconds)
$MaxParallelJobs  = 50         # Runspace pool size for port scanning
$OutputDir        = $PSScriptRoot  # Where result files are written


# =============================================================================
#  HELPER: Expand a CIDR block into a list of host IPs
# =============================================================================
function Expand-Cidr {
    param([string]$Cidr)

    $parts     = $Cidr -split '/'
    $baseIp    = $parts[0]
    $prefixLen = [int]$parts[1]

    $ipBytes = ([System.Net.IPAddress]::Parse($baseIp)).GetAddressBytes()
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($ipBytes) }
    $ipInt = [BitConverter]::ToUInt32($ipBytes, 0)

    $mask       = if ($prefixLen -eq 0) { 0 } else { [uint32]([uint32]0xFFFFFFFF -shl (32 - $prefixLen)) }
    $networkInt = $ipInt -band $mask
    $broadcast  = $networkInt -bor (-bnot $mask -band 0xFFFFFFFF)
    $hostCount  = $broadcast - $networkInt - 1

    if ($hostCount -le 0) {
        Write-Warning "Subnet $Cidr has no usable hosts — skipping."
        return @()
    }

    $ips = [System.Collections.Generic.List[string]]::new()
    for ($i = 1; $i -le $hostCount; $i++) {
        $hostInt = $networkInt + [uint32]$i
        $b = [BitConverter]::GetBytes([uint32]$hostInt)
        if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($b) }
        $ips.Add(("{0}.{1}.{2}.{3}" -f $b[0], $b[1], $b[2], $b[3]))
    }
    return $ips
}


# =============================================================================
#  HELPER: HTTP/HTTPS fingerprint — title, headers, redirect, TLS CN
# =============================================================================
function Get-HttpFingerprint {
    param([string]$IP, [int]$Port, [int]$TimeoutSec)

    $scheme = if ($Port -eq 443) { "https" } else { "http" }
    $url    = "${scheme}://${IP}:${Port}/"

    $result = [ordered]@{
        Url         = $url
        StatusCode  = $null
        Title       = $null
        Server      = $null
        PoweredBy   = $null
        ContentType = $null
        RedirectTo  = $null
        TlsCN       = $null
        Error       = $null
    }

    # Trust all TLS certificates (handles self-signed certs on LAN hosts)
    if (-not ("TrustAll" -as [type])) {
        Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAll : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert,
        WebRequest req, int problem) { return true; }
}
"@ -ErrorAction SilentlyContinue
    }
    [System.Net.ServicePointManager]::CertificatePolicy = [TrustAll]::new()
    [System.Net.ServicePointManager]::SecurityProtocol  =
        [System.Net.SecurityProtocolType]::Tls12 -bor
        [System.Net.SecurityProtocolType]::Tls11 -bor
        [System.Net.SecurityProtocolType]::Tls

    try {
        $req                   = [System.Net.HttpWebRequest]::Create($url)
        $req.Timeout           = $TimeoutSec * 1000
        $req.ReadWriteTimeout  = $TimeoutSec * 1000
        $req.AllowAutoRedirect = $false
        $req.UserAgent         = "Mozilla/5.0 (SubnetScanner/1.0; +recon)"
        $req.Headers.Add("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")

        $resp = $req.GetResponse()

        $result.StatusCode  = [int]$resp.StatusCode
        $result.Server      = $resp.Headers["Server"]
        $result.PoweredBy   = $resp.Headers["X-Powered-By"]
        $result.ContentType = $resp.Headers["Content-Type"]

        if ($result.StatusCode -in 301, 302, 303, 307, 308) {
            $result.RedirectTo = $resp.Headers["Location"]
        }

        # TLS certificate CN
        if ($Port -eq 443) {
            try {
                $sp = [System.Net.ServicePointManager]::FindServicePoint($url)
                if ($sp.Certificate) {
                    $result.TlsCN = $sp.Certificate.Subject -replace '^.*?CN=([^,]+).*$', '$1'
                }
            } catch { }
        }

        # Read up to 32 KB of body to extract <title>
        $stream = $resp.GetResponseStream()
        $buf    = New-Object byte[] 32768
        $read   = $stream.Read($buf, 0, $buf.Length)
        $stream.Close(); $resp.Close()

        if ($read -gt 0) {
            $body = [System.Text.Encoding]::UTF8.GetString($buf, 0, $read)
            if ($body -match '(?i)<title[^>]*>([\s\S]*?)</title>') {
                $result.Title = ($Matches[1] -replace '\s+', ' ').Trim()
            }
        }
    }
    catch [System.Net.WebException] {
        $webEx = $_.Exception
        if ($webEx.Response) {
            $result.StatusCode = [int]$webEx.Response.StatusCode
        }
        $result.Error = $webEx.Message
    }
    catch {
        $result.Error = $_.Exception.Message
    }

    return $result
}


# =============================================================================
#  MAIN
# =============================================================================
$Timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$JsonFile   = Join-Path $OutputDir "scan_${Timestamp}.json"
$ReportFile = Join-Path $OutputDir "scan_${Timestamp}.txt"

Write-Host "`n[*] Subnet Scanner — $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "[*] Target subnets : $($Subnets -join ', ')"  -ForegroundColor Cyan
Write-Host "[*] Ports           : $($PortsToScan -join ', ')" -ForegroundColor Cyan
Write-Host "[*] Output          : $OutputDir`n" -ForegroundColor Cyan

# ── Build full IP list ────────────────────────────────────────────────────────
$AllIPs = [System.Collections.Generic.List[string]]::new()
foreach ($subnet in $Subnets) {
    $expanded = Expand-Cidr $subnet
    Write-Host "[*] $subnet  =>  $($expanded.Count) hosts" -ForegroundColor Gray
    $AllIPs.AddRange($expanded)
}
Write-Host "[*] Total hosts to probe: $($AllIPs.Count)`n" -ForegroundColor Yellow


# ── Phase 1: Parallel TCP port scan ──────────────────────────────────────────
Write-Host "[*] Phase 1 — TCP port scan (runspace pool, size=$MaxParallelJobs) ..." -ForegroundColor Cyan

$pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $MaxParallelJobs)
$pool.Open()

$jobs = [System.Collections.Generic.List[hashtable]]::new()

$portCheckScript = {
    param($ip, $ports, $timeoutMs)
    $open = @()
    foreach ($p in $ports) {
        try {
            $tcp = [System.Net.Sockets.TcpClient]::new()
            $iar = $tcp.BeginConnect($ip, $p, $null, $null)
            $ok  = $iar.AsyncWaitHandle.WaitOne($timeoutMs, $false)
            if ($ok -and $tcp.Connected) { $open += $p }
            $tcp.Close()
        } catch { }
    }
    [PSCustomObject]@{ IP = $ip; OpenPorts = $open }
}

foreach ($ip in $AllIPs) {
    $ps = [System.Management.Automation.PowerShell]::Create()
    $ps.RunspacePool = $pool
    $null = $ps.AddScript($portCheckScript).AddArgument($ip).AddArgument($PortsToScan).AddArgument($ConnectTimeoutMs)
    $jobs.Add(@{ PS = $ps; Handle = $ps.BeginInvoke() })
}

$liveHosts = [System.Collections.Generic.List[PSCustomObject]]::new()
$done = 0
foreach ($job in $jobs) {
    $res = $job.PS.EndInvoke($job.Handle)
    $job.PS.Dispose()
    $done++
    if ($res -and $res.OpenPorts.Count -gt 0) {
        $liveHosts.Add($res)
        Write-Host "  [+] $($res.IP)  open: $($res.OpenPorts -join ',')" -ForegroundColor Green
    }
    if ($done % 100 -eq 0) {
        Write-Host "      ... scanned $done / $($AllIPs.Count)" -ForegroundColor DarkGray
    }
}
$pool.Close(); $pool.Dispose()

Write-Host "`n[*] Phase 1 done — $($liveHosts.Count) host(s) with open web ports.`n" -ForegroundColor Yellow


# ── Phase 2: HTTP fingerprinting ─────────────────────────────────────────────
Write-Host "[*] Phase 2 — HTTP fingerprinting ..." -ForegroundColor Cyan

$ScanResults = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($h in $liveHosts) {
    $entry = [ordered]@{
        IP        = $h.IP
        OpenPorts = $h.OpenPorts
        HTTP      = $null
        HTTPS     = $null
        ScannedAt = (Get-Date -Format "o")
    }

    foreach ($port in $h.OpenPorts) {
        $fp     = Get-HttpFingerprint -IP $h.IP -Port $port -TimeoutSec $HttpTimeoutSec
        $proto  = if ($port -eq 443) { "HTTPS" } else { "HTTP " }
        $status = if ($fp.StatusCode) { $fp.StatusCode } else { "???" }
        $title  = if ($fp.Title)      { $fp.Title }      else { "(no title)" }
        $server = if ($fp.Server)     { $fp.Server }     else { "(unknown)" }

        Write-Host ("  [{0}] {1,-15} {2}  server={3}  title={4}" -f $proto, $h.IP, $status, $server, $title) -ForegroundColor White

        if ($port -eq 80)  { $entry.HTTP  = $fp }
        if ($port -eq 443) { $entry.HTTPS = $fp }
    }

    $ScanResults.Add([PSCustomObject]$entry)
}


# ── Phase 3: Write output files ───────────────────────────────────────────────
Write-Host "`n[*] Phase 3 — Writing output files ..." -ForegroundColor Cyan

# JSON (full structured data)
$ScanResults | ConvertTo-Json -Depth 10 | Set-Content -Path $JsonFile -Encoding UTF8

# Human-readable TXT report
$sb = [System.Text.StringBuilder]::new()
$null = $sb.AppendLine(("=" * 80))
$null = $sb.AppendLine("  SUBNET SCAN REPORT")
$null = $sb.AppendLine("  Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
$null = $sb.AppendLine("  Subnets   : $($Subnets -join ', ')")
$null = $sb.AppendLine("  Ports     : $($PortsToScan -join ', ')")
$null = $sb.AppendLine("  Live hosts: $($ScanResults.Count)")
$null = $sb.AppendLine(("=" * 80))
$null = $sb.AppendLine()

foreach ($r in $ScanResults) {
    $null = $sb.AppendLine(("-" * 60))
    $null = $sb.AppendLine("  Host      : $($r.IP)")
    $null = $sb.AppendLine("  Open Ports: $($r.OpenPorts -join ', ')")
    $null = $sb.AppendLine("  Scanned   : $($r.ScannedAt)")
    $null = $sb.AppendLine()

    foreach ($proto in @("HTTP", "HTTPS")) {
        $fp = if ($proto -eq "HTTP") { $r.HTTP } else { $r.HTTPS }
        if ($null -eq $fp) { continue }

        $null = $sb.AppendLine("  [$proto]")
        $null = $sb.AppendLine("    URL          : $($fp.Url)")
        $null = $sb.AppendLine("    Status Code  : $($fp.StatusCode)")
        $null = $sb.AppendLine("    Title        : $($fp.Title)")
        $null = $sb.AppendLine("    Server       : $($fp.Server)")
        $null = $sb.AppendLine("    X-Powered-By : $($fp.PoweredBy)")
        $null = $sb.AppendLine("    Content-Type : $($fp.ContentType)")
        if ($fp.RedirectTo) { $null = $sb.AppendLine("    Redirect To  : $($fp.RedirectTo)") }
        if ($fp.TlsCN)      { $null = $sb.AppendLine("    TLS Cert CN  : $($fp.TlsCN)") }
        if ($fp.Error)      { $null = $sb.AppendLine("    Error        : $($fp.Error)") }
        $null = $sb.AppendLine()
    }
}

$null = $sb.AppendLine(("=" * 80))
$null = $sb.AppendLine("  END OF REPORT")
$null = $sb.AppendLine(("=" * 80))

$sb.ToString() | Set-Content -Path $ReportFile -Encoding UTF8

Write-Host "[+] JSON   : $JsonFile"   -ForegroundColor Green
Write-Host "[+] Report : $ReportFile" -ForegroundColor Green
Write-Host "`n[*] Scan complete.`n"   -ForegroundColor Cyan
