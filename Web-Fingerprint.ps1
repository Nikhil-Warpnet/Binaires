# Subnets to scan
$subnets = @("10.2.0.0/24", "10.2.7.0/24", "10.1.176.0/24", "10.1.178.0/24")
$out     = "H:\_Appsense_\Desktop\scan_web.txt"

function Get-IPs($cidr) {
    $b = $cidr -split '/'; $prefix = [int]$b[1]
    $bytes = ([Net.IPAddress]::Parse($b[0])).GetAddressBytes()
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes) }
    $base = [BitConverter]::ToUInt32($bytes, 0)
    $mask = [uint32]([uint32]0xFFFFFFFF -shl (32 - $prefix))
    $net  = $base -band $mask
    $cnt  = ($net -bor (-bnot $mask -band 0xFFFFFFFF)) - $net - 1
    1..$cnt | ForEach-Object {
        $n = $net + [uint32]$_; $x = [BitConverter]::GetBytes([uint32]$n)
        if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($x) }
        "$($x[0]).$($x[1]).$($x[2]).$($x[3])"
    }
}

function Test-Port($ip, $port) {
    try {
        $t = [Net.Sockets.TcpClient]::new()
        $r = $t.BeginConnect($ip, $port, $null, $null).AsyncWaitHandle.WaitOne(600, $false)
        $ok = $r -and $t.Connected; $t.Close(); return $ok
    } catch { return $false }
}

function Get-Fingerprint($ip, $port) {
    Add-Type @"
using System.Net; using System.Security.Cryptography.X509Certificates;
public class ST : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint s, X509Certificate c, WebRequest r, int e) { return true; } }
"@ -EA SilentlyContinue
    [Net.ServicePointManager]::CertificatePolicy = [ST]::new()
    [Net.ServicePointManager]::SecurityProtocol  = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11

    $url = "$(if($port -eq 443){'https'}else{'http'})://${ip}:${port}/"
    $fp  = [ordered]@{ URL=$url; Status=$null; Title=$null; Server=$null; PoweredBy=$null; Redirect=$null; TlsCN=$null }
    try {
        $req = [Net.HttpWebRequest]::Create($url)
        $req.Timeout = $req.ReadWriteTimeout = 5000
        $req.AllowAutoRedirect = $false
        $req.UserAgent = "Mozilla/5.0"
        $res = $req.GetResponse()
        $fp.Status    = [int]$res.StatusCode
        $fp.Server    = $res.Headers["Server"]
        $fp.PoweredBy = $res.Headers["X-Powered-By"]
        $fp.Redirect  = $res.Headers["Location"]
        if ($port -eq 443) {
            $sp = [Net.ServicePointManager]::FindServicePoint($url)
            if ($sp.Certificate) { $fp.TlsCN = $sp.Certificate.Subject -replace '^.*?CN=([^,]+).*$','$1' }
        }
        $buf = New-Object byte[] 32768
        $n   = $res.GetResponseStream().Read($buf, 0, $buf.Length)
        $res.Close()
        $body = [Text.Encoding]::UTF8.GetString($buf, 0, $n)
        if ($body -match '(?i)<title[^>]*>([\s\S]*?)</title>') { $fp.Title = ($Matches[1] -replace '\s+',' ').Trim() }
    } catch [Net.WebException] {
        if ($_.Exception.Response) { $fp.Status = [int]$_.Exception.Response.StatusCode }
    } catch {}
    return $fp
}

# ── scan ──────────────────────────────────────────────────────────────────────
$lines = [Collections.Generic.List[string]]::new()
$lines.Add("SCAN  $(Get-Date -f 'yyyy-MM-dd HH:mm:ss')  subnets: $($subnets -join ', ')")
$lines.Add("=" * 70)

foreach ($subnet in $subnets) {
    Write-Host "`n[*] $subnet" -ForegroundColor Cyan
    foreach ($ip in (Get-IPs $subnet)) {
        $open = @(80, 443) | Where-Object { Test-Port $ip $_ }
        if (-not $open) { continue }
        Write-Host "  [+] $ip  ports: $($open -join ',')" -ForegroundColor Green
        $lines.Add("`nHost: $ip   ports: $($open -join ',')")
        foreach ($port in $open) {
            $fp = Get-Fingerprint $ip $port
            $proto = if ($port -eq 443) { "HTTPS" } else { "HTTP " }
            Write-Host ("    [{0}] {1}  server={2}  title={3}" -f $proto, $fp.Status, $fp.Server, $fp.Title)
            $lines.Add("  [$proto]")
            $lines.Add("    URL         : $($fp.URL)")
            $lines.Add("    Status      : $($fp.Status)")
            $lines.Add("    Title       : $($fp.Title)")
            $lines.Add("    Server      : $($fp.Server)")
            $lines.Add("    X-Powered-By: $($fp.PoweredBy)")
            if ($fp.Redirect) { $lines.Add("    Redirect    : $($fp.Redirect)") }
            if ($fp.TlsCN)    { $lines.Add("    TLS Cert CN : $($fp.TlsCN)") }
        }
        $lines.Add("-" * 70)
    }
}

New-Item -ItemType Directory -Force -Path (Split-Path $out) | Out-Null
$lines | Set-Content $out -Encoding UTF8
Write-Host "`n[+] Saved to $out" -ForegroundColor Yellow
