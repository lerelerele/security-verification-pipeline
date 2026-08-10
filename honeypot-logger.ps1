# honeypot-logger.ps1 — HTTP logger para el honeypot en PowerShell
# Responde 200 a CUALQUIER path. Logea todo en JSONL.
# No necesita Python. Nativo de Windows.
#
# Uso:
#   .\honeypot-logger.ps1 -Port 80 -LogFile C:\honeypot.jsonl

param(
    [int]$Port = 80,
    [string]$LogFile = "C:\honeypot.jsonl",
    [string]$Bind = "0.0.0.0"
)

# Ensure log dir exists
$logDir = Split-Path $LogFile -Parent
if ($logDir -and -not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

$script:RequestCounter = 0

function Classify-Request {
    param([string]$Path, [string]$UA, [string]$Body)
    $classifications = @()
    $pathLower = $Path.ToLower()
    $uaLower = $UA.ToLower()

    if ($pathLower -match "/api/status/check" -or $pathLower -match "/api/verify") { $classifications += "honeypot_verify" }
    if ($pathLower -match "/mcp" -or $pathLower -match "/sse") { $classifications += "mcp_probe" }
    if ($pathLower -match "/v1/models" -or $pathLower -match "/v1/completions" -or $pathLower -match "/v1/embeddings") { $classifications += "llm_api_probe" }
    if ($uaLower -match "libredtail") { $classifications += "libredtail_scanner" }
    if ($uaLower -match "zgrab") { $classifications += "zgrab_scanner" }
    if ($uaLower -match "censys") { $classifications += "censys_scanner" }
    if ($uaLower -match "masscan") { $classifications += "masscan" }
    if ($uaLower -match "palo alto") { $classifications += "palo_alto_expanse" }
    if ($uaLower -match "powershell") { $classifications += "powershell_agent" }
    if ($uaLower -match "python-requests" -or $uaLower -match "python-httpx") { $classifications += "python_bot" }
    if ($uaLower -match "winrm") { $classifications += "winrm_brute" }
    if ($uaLower -match "wget") { $classifications += "wget_scanner" }
    if ($pathLower -match "phpunit") { $classifications += "phpunit_rce" }
    if ($pathLower -match "think" -and $pathLower -match "invokefunction") { $classifications += "thinkphp_rce" }
    if ($pathLower -match "/\.env" -or $pathLower -match "/\.aws" -or $pathLower -match "/\.git") { $classifications += "cred_harvest" }
    if ($pathLower -match "/\.ssh") { $classifications += "ssh_key_harvest" }
    if ($pathLower -match "/wsman") { $classifications += "winrm_probe" }
    if ($pathLower -match "/sdk/weblanguage") { $classifications += "cctv_recon" }
    if ($pathLower -match "/actuator") { $classifications += "spring_actuator" }
    if ($pathLower -match "/geoserver") { $classifications += "geoserver_recon" }
    if ($pathLower -match "/_layouts" -or $pathLower -match "/_vti") { $classifications += "sharepoint_recon" }
    if ($classifications.Count -eq 0) { $classifications += "unknown" }
    return $classifications
}

# Create listener
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://${Bind}:${Port}/")
$listener.Start()

Write-Host "Honeypot logger listening on ${Bind}:${Port}"
Write-Host "Logging to $LogFile"
Write-Host "PID: $PID"
Write-Host "Press Ctrl+C to stop."

try {
    while ($listener.IsListening) {
        $context = $listener.GetContext()
        $script:RequestCounter++

        $request = $context.Request
        $response = $context.Response

        # Collect request info
        $clientIp = $request.RemoteEndPoint.Address.ToString()
        $clientPort = $request.RemoteEndPoint.Port
        $method = $request.HttpMethod
        $rawUrl = $request.Url.AbsolutePath
        $queryString = $request.Url.Query

        # Parse query params
        $queryParams = @{}
        if ($request.Url.Query) {
            $qs = $request.Url.Query.TrimStart("?")
            foreach ($pair in $qs -split "&") {
                $kv = $pair -split "=", 2
                if ($kv.Count -eq 2) {
                    $queryParams[$kv[0]] = $kv[1]
                }
            }
        }

        # Collect headers
        $headers = @{}
        for ($i = 0; $i -lt $request.Headers.Count; $i++) {
            $key = $request.Headers.GetKey($i)
            $val = $request.Headers.Get($i)
            if ($val.Length -lt 5000) {
                $headers[$key] = $val
            } else {
                $headers[$key] = $val.Substring(0, 200) + "...[TRUNCATED]"
            }
        }

        $ua = $headers["User-Agent"]
        if (-not $ua) { $ua = "" }

        # Read body
        $bodyStr = $null
        $bodySize = 0
        if ($request.ContentLength64 -gt 0) {
            $bodySize = [int]$request.ContentLength64
            $stream = $request.InputStream
            $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::UTF8)
            $bodyStr = $reader.ReadToEnd()
            if ($bodyStr.Length -gt 10000) {
                $bodyStr = $bodyStr.Substring(0, 10000) + "...[TRUNCATED]"
            }
        }

        # Classify
        $classifications = Classify-Request -Path $rawUrl -UA $ua -Body $bodyStr

        # Build log entry
        $entry = @{
            id = $script:RequestCounter
            timestamp = (Get-Date).ToUniversalTime().ToString("o")
            client_ip = $clientIp
            client_port = $clientPort
            method = $method
            path = $rawUrl
            query_params = $queryParams
            headers = $headers
            user_agent = $ua
            body = $bodyStr
            body_size = $bodySize
            classifications = $classifications
        }

        $jsonLine = $entry | ConvertTo-Json -Compress -Depth 5
        Add-Content -Path $LogFile -Value $jsonLine -Encoding UTF8

        # Respond 200
        $responseBody = [System.Text.Encoding]::UTF8.GetBytes('{"status":"ok"}')
        $response.StatusCode = 200
        $response.ContentType = "application/json"
        $response.ContentLength64 = $responseBody.Length
        $response.Headers.Add("Server", "nginx/1.24.0")
        $response.Headers.Add("X-Powered-By", "PHP/8.2.0")
        $response.OutputStream.Write($responseBody, 0, $responseBody.Length)
        $response.OutputStream.Close()
    }
} catch {
    Write-Host "`nShutting down... $_"
} finally {
    $listener.Stop()
}