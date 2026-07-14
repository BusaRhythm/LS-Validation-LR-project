[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Net.Http
$CandidatePorts = @(8090, 8899)
$BindAddress = [System.Net.IPAddress]::Loopback
$RootDirectory = $PSScriptRoot

$ClientHandler = {
    param(
        [System.Net.Sockets.TcpClient] $Client,
        [string] $RootDirectory,
        [int] $LocalPort
    )

    $ErrorActionPreference = 'Stop'

    function Write-HttpResponse {
        param(
            [System.IO.Stream] $Stream,
            [int] $StatusCode,
            [string] $Reason,
            [string] $ContentType,
            [byte[]] $Body,
            [hashtable] $AdditionalHeaders = @{}
        )

        $headerLines = [System.Collections.Generic.List[string]]::new()
        $headerLines.Add("HTTP/1.1 $StatusCode $Reason")
        $headerLines.Add("Content-Type: $ContentType")
        $headerLines.Add("Content-Length: $($Body.Length)")
        $headerLines.Add('Connection: close')
        $headerLines.Add('X-Content-Type-Options: nosniff')
        $headerLines.Add('Referrer-Policy: no-referrer')
        foreach ($entry in $AdditionalHeaders.GetEnumerator()) {
            $headerLines.Add("$($entry.Key): $($entry.Value)")
        }
        $headerText = ($headerLines -join "`r`n") + "`r`n`r`n"
        $headerBytes = [System.Text.Encoding]::ASCII.GetBytes($headerText)
        $Stream.Write($headerBytes, 0, $headerBytes.Length)
        if ($Body.Length -gt 0) {
            $Stream.Write($Body, 0, $Body.Length)
        }
        $Stream.Flush()
    }

    function Write-JsonError {
        param(
            [System.IO.Stream] $Stream,
            [int] $StatusCode,
            [string] $Reason,
            [string] $Code,
            [string] $Message
        )

        $json = @{ error = @{ code = $Code; message = $Message } } | ConvertTo-Json -Compress
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        Write-HttpResponse -Stream $Stream -StatusCode $StatusCode -Reason $Reason -ContentType 'application/json; charset=utf-8' -Body $bytes -AdditionalHeaders @{ 'Cache-Control' = 'no-store' }
    }

    function Read-HttpRequest {
        param([System.IO.Stream] $Stream)

        $headerBuffer = [System.IO.MemoryStream]::new()
        $matchState = 0
        while ($headerBuffer.Length -lt 65536) {
            $value = $Stream.ReadByte()
            if ($value -lt 0) { throw 'The client disconnected before sending complete headers.' }
            $headerBuffer.WriteByte([byte]$value)
            switch ($matchState) {
                0 { if ($value -eq 13) { $matchState = 1 } }
                1 { if ($value -eq 10) { $matchState = 2 } elseif ($value -ne 13) { $matchState = 0 } }
                2 { if ($value -eq 13) { $matchState = 3 } else { $matchState = 0 } }
                3 { if ($value -eq 10) { $matchState = 4 } else { $matchState = 0 } }
            }
            if ($matchState -eq 4) { break }
        }
        if ($matchState -ne 4) { throw 'Request headers are too large.' }

        $headerText = [System.Text.Encoding]::ASCII.GetString($headerBuffer.ToArray())
        $lines = $headerText -split "`r`n"
        $requestParts = $lines[0] -split ' '
        if ($requestParts.Count -ne 3 -or $requestParts[2] -notmatch '^HTTP/1\.[01]$') {
            throw 'Malformed HTTP request line.'
        }

        $headers = @{}
        for ($index = 1; $index -lt $lines.Count; $index++) {
            if ([string]::IsNullOrEmpty($lines[$index])) { break }
            $separator = $lines[$index].IndexOf(':')
            if ($separator -le 0) { throw 'Malformed HTTP header.' }
            $name = $lines[$index].Substring(0, $separator).Trim().ToLowerInvariant()
            $headers[$name] = $lines[$index].Substring($separator + 1).Trim()
        }

        $contentLength = 0
        if ($headers.ContainsKey('content-length')) {
            if (-not [int]::TryParse($headers['content-length'], [ref]$contentLength) -or $contentLength -lt 0 -or $contentLength -gt 1048576) {
                throw 'Invalid or excessive Content-Length.'
            }
        }

        $body = [byte[]]::new($contentLength)
        $read = 0
        while ($read -lt $contentLength) {
            $count = $Stream.Read($body, $read, $contentLength - $read)
            if ($count -le 0) { throw 'The client disconnected before sending the request body.' }
            $read += $count
        }

        return [pscustomobject]@{
            Method = $requestParts[0].ToUpperInvariant()
            Target = $requestParts[1]
            Headers = $headers
            Body = $body
        }
    }

    function Get-NormalizedPmHost {
        param([object] $Value)

        if ($Value -isnot [string]) { return $null }
        $hostValue = $Value.Trim()
        if ([string]::IsNullOrWhiteSpace($hostValue) -or $hostValue.Length -gt 253) { return $null }
        if ($hostValue -match '^[a-z][a-z0-9+.-]*://' -or $hostValue -match '[/\\?#@\s:]') { return $null }
        if ($hostValue.Equals('localhost', [System.StringComparison]::OrdinalIgnoreCase)) { return 'localhost' }

        $address = $null
        if ([System.Net.IPAddress]::TryParse($hostValue, [ref]$address)) {
            if ($address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
                return $address.ToString()
            }
            return $null
        }

        $labels = $hostValue.Split('.')
        if ($labels.Count -lt 2) { return $null }
        foreach ($label in $labels) {
            if ($label.Length -lt 1 -or $label.Length -gt 63 -or $label -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$') {
                return $null
            }
        }
        return $hostValue.ToLowerInvariant()
    }

    function Test-AllowedApiPath {
        param([object] $Value)

        if ($Value -isnot [string]) { return $false }
        return $Value -match '^/lr-admin-api/logsources/\?offset=(?:0|[1-9][0-9]*)&count=1000&recordStatus=all$' -or
               $Value -match '^/lr-admin-api/logsources/[0-9]+$'
    }

    function Invoke-LogRhythmRequest {
        param(
            [string] $HostName,
            [string] $Token,
            [string] $ApiPath,
            [System.Net.Sockets.TcpClient] $ClientConnection
        )

        $handler = $null
        $httpClient = $null
        $request = $null
        $response = $null
        $cancellation = $null
        $clientDisconnected = $false
        $timedOut = $false
        try {
            $handler = [System.Net.Http.HttpClientHandler]::new()
            $handler.UseProxy = $false
            $handler.AllowAutoRedirect = $false
            $handler.ServerCertificateCustomValidationCallback = [System.Net.Http.HttpClientHandler]::DangerousAcceptAnyServerCertificateValidator

            $httpClient = [System.Net.Http.HttpClient]::new($handler, $true)
            $httpClient.Timeout = [System.Threading.Timeout]::InfiniteTimeSpan
            $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, "https://$HostName`:8501$ApiPath")
            $request.Headers.Accept.Add([System.Net.Http.Headers.MediaTypeWithQualityHeaderValue]::new('application/json'))
            $request.Headers.Authorization = [System.Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $Token)
            $cancellation = [System.Threading.CancellationTokenSource]::new()
            $responseTask = $httpClient.SendAsync($request, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead, $cancellation.Token)

            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            while (-not $responseTask.IsCompleted) {
                if ($ClientConnection.Client.Poll(1000, [System.Net.Sockets.SelectMode]::SelectRead) -and $ClientConnection.Client.Available -eq 0) {
                    $clientDisconnected = $true
                    $cancellation.Cancel()
                    break
                }
                if ($stopwatch.Elapsed.TotalSeconds -ge 30) {
                    $timedOut = $true
                    $cancellation.Cancel()
                    break
                }
                Start-Sleep -Milliseconds 20
            }
            $stopwatch.Stop()
            if ($clientDisconnected) { return @{ Cancelled = $true } }
            if ($timedOut) {
                return @{ Error = @{ Status = 504; Reason = 'Gateway Timeout'; Code = 'timeout'; Message = 'The Platform Manager request timed out after 30 seconds.' } }
            }
            $response = $responseTask.GetAwaiter().GetResult()
            $status = [int]$response.StatusCode
            if (-not $response.IsSuccessStatusCode) {
                switch ($status) {
                    401 { return @{ Error = @{ Status = 401; Reason = 'Unauthorized'; Code = 'invalid-token'; Message = 'Authorization failed (HTTP 401). Verify the Bearer Token.' } } }
                    403 { return @{ Error = @{ Status = 403; Reason = 'Forbidden'; Code = 'invalid-token'; Message = 'Authorization failed (HTTP 403). The token does not have permission to read log sources.' } } }
                    404 { return @{ Error = @{ Status = 404; Reason = 'Not Found'; Code = 'not-found'; Message = 'The requested LogRhythm log source was not found (HTTP 404).' } } }
                    default { return @{ Error = @{ Status = 502; Reason = 'Bad Gateway'; Code = 'upstream-http-error'; Message = "The Platform Manager returned HTTP $status." } } }
                }
            }
            $responseBody = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        } catch {
            $exception = $_.Exception
            if ($clientDisconnected) { return @{ Cancelled = $true } }
            if ($timedOut) {
                return @{ Error = @{ Status = 504; Reason = 'Gateway Timeout'; Code = 'timeout'; Message = 'The Platform Manager request timed out after 30 seconds.' } }
            }

            $cursor = $exception
            $connectionRefused = $false
            $nameResolutionFailed = $false
            while ($cursor) {
                if ($cursor -is [System.Net.Sockets.SocketException] -and $cursor.SocketErrorCode -eq [System.Net.Sockets.SocketError]::ConnectionRefused) {
                    $connectionRefused = $true
                    break
                }
                if ($cursor -is [System.Net.Sockets.SocketException] -and $cursor.SocketErrorCode -eq [System.Net.Sockets.SocketError]::HostNotFound) {
                    $nameResolutionFailed = $true
                    break
                }
                if ($cursor -is [System.Net.WebException] -and $cursor.Status -eq [System.Net.WebExceptionStatus]::NameResolutionFailure) {
                    $nameResolutionFailed = $true
                    break
                }
                $cursor = $cursor.InnerException
            }
            if ($connectionRefused) {
                return @{ Error = @{ Status = 502; Reason = 'Bad Gateway'; Code = 'connection-refused'; Message = 'The Platform Manager refused the connection on HTTPS port 8501.' } }
            }
            if ($nameResolutionFailed) {
                return @{ Error = @{ Status = 502; Reason = 'Bad Gateway'; Code = 'host-not-found'; Message = 'The Platform Manager host could not be resolved.' } }
            }
            return @{ Error = @{ Status = 502; Reason = 'Bad Gateway'; Code = 'connection-failed'; Message = 'The local proxy could not connect to the Platform Manager on HTTPS port 8501.' } }
        } finally {
            if ($response) { $response.Dispose() }
            if ($request) { $request.Dispose() }
            if ($cancellation) { $cancellation.Dispose() }
            if ($httpClient) { $httpClient.Dispose() }
            elseif ($handler) { $handler.Dispose() }
        }

        try {
            $null = $responseBody | ConvertFrom-Json -ErrorAction Stop
        } catch {
            return @{ Error = @{ Status = 502; Reason = 'Bad Gateway'; Code = 'invalid-json'; Message = 'The Platform Manager returned a response that was not valid JSON.' } }
        }

        return @{ Body = [System.Text.Encoding]::UTF8.GetBytes($responseBody) }
    }

    try {
        $Client.NoDelay = $true
        $stream = $Client.GetStream()
        $stream.ReadTimeout = 10000
        $stream.WriteTimeout = 10000

        try {
            $request = Read-HttpRequest -Stream $stream
        } catch {
            Write-JsonError -Stream $stream -StatusCode 400 -Reason 'Bad Request' -Code 'bad-request' -Message 'The local server received a malformed request.'
            return
        }

        $expectedHosts = @("localhost:$LocalPort", "127.0.0.1:$LocalPort")
        if (-not $request.Headers.ContainsKey('host') -or $request.Headers['host'].ToLowerInvariant() -notin $expectedHosts) {
            Write-JsonError -Stream $stream -StatusCode 400 -Reason 'Bad Request' -Code 'invalid-local-host' -Message "This server accepts requests only through localhost:$LocalPort or 127.0.0.1:$LocalPort."
            return
        }

        if ($request.Headers.ContainsKey('origin')) {
            $allowedOrigins = @("http://localhost:$LocalPort", "http://127.0.0.1:$LocalPort")
            if ($request.Headers['origin'].ToLowerInvariant() -notin $allowedOrigins) {
                Write-JsonError -Stream $stream -StatusCode 403 -Reason 'Forbidden' -Code 'origin-rejected' -Message 'Cross-origin proxy requests are not allowed.'
                return
            }
        }

        if ($request.Method -eq 'GET') {
            $staticFiles = @{
                '/' = @{ Name = 'index.html'; Type = 'text/html; charset=utf-8' }
                '/index.html' = @{ Name = 'index.html'; Type = 'text/html; charset=utf-8' }
                '/styles.css' = @{ Name = 'styles.css'; Type = 'text/css; charset=utf-8' }
                '/app.js' = @{ Name = 'app.js'; Type = 'text/javascript; charset=utf-8' }
                '/xlsx.full.min.js' = @{ Name = 'xlsx.full.min.js'; Type = 'text/javascript; charset=utf-8' }
            }
            if (-not $staticFiles.ContainsKey($request.Target)) {
                Write-JsonError -Stream $stream -StatusCode 404 -Reason 'Not Found' -Code 'local-not-found' -Message 'The requested local resource was not found.'
                return
            }
            $asset = $staticFiles[$request.Target]
            $filePath = [System.IO.Path]::Combine($RootDirectory, $asset.Name)
            if (-not [System.IO.File]::Exists($filePath)) {
                Write-JsonError -Stream $stream -StatusCode 500 -Reason 'Internal Server Error' -Code 'missing-file' -Message "Required application file $($asset.Name) is missing."
                return
            }
            $bytes = [System.IO.File]::ReadAllBytes($filePath)
            Write-HttpResponse -Stream $stream -StatusCode 200 -Reason 'OK' -ContentType $asset.Type -Body $bytes -AdditionalHeaders @{
                'Cache-Control' = 'no-store'
                'Content-Security-Policy' = "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
            }
            return
        }

        if ($request.Method -ne 'POST' -or $request.Target -ne '/proxy') {
            Write-JsonError -Stream $stream -StatusCode 405 -Reason 'Method Not Allowed' -Code 'method-not-allowed' -Message 'Only GET requests for application files and POST requests to /proxy are allowed.'
            return
        }
        if (-not $request.Headers.ContainsKey('content-type') -or $request.Headers['content-type'] -notmatch '^application/json(?:\s*;|$)') {
            Write-JsonError -Stream $stream -StatusCode 415 -Reason 'Unsupported Media Type' -Code 'invalid-content-type' -Message 'Proxy requests must use application/json.'
            return
        }

        try {
            $bodyText = [System.Text.Encoding]::UTF8.GetString($request.Body)
            $payload = $bodyText | ConvertFrom-Json -ErrorAction Stop
        } catch {
            Write-JsonError -Stream $stream -StatusCode 400 -Reason 'Bad Request' -Code 'invalid-json' -Message 'The proxy request body was not valid JSON.'
            return
        }

        $pmHost = Get-NormalizedPmHost -Value $payload.host
        if (-not $pmHost) {
            Write-JsonError -Stream $stream -StatusCode 400 -Reason 'Bad Request' -Code 'invalid-host' -Message 'Enter a valid Platform Manager FQDN, IPv4 address, or localhost without a scheme, port, or path.'
            return
        }
        if ($payload.token -isnot [string] -or [string]::IsNullOrWhiteSpace($payload.token) -or $payload.token.Length -gt 16384 -or $payload.token -match '[\x00-\x1F\x7F]') {
            Write-JsonError -Stream $stream -StatusCode 401 -Reason 'Unauthorized' -Code 'invalid-token' -Message 'A Bearer Token is required.'
            return
        }
        if (-not (Test-AllowedApiPath -Value $payload.path)) {
            Write-JsonError -Stream $stream -StatusCode 400 -Reason 'Bad Request' -Code 'path-rejected' -Message 'The requested API path is not allowed by this restricted proxy.'
            return
        }

        $result = Invoke-LogRhythmRequest -HostName $pmHost -Token $payload.token -ApiPath $payload.path -ClientConnection $Client
        $payload.token = $null
        $bodyText = $null
        if ($result.Cancelled) { return }
        if ($result.Error) {
            Write-JsonError -Stream $stream -StatusCode $result.Error.Status -Reason $result.Error.Reason -Code $result.Error.Code -Message $result.Error.Message
            return
        }
        Write-HttpResponse -Stream $stream -StatusCode 200 -Reason 'OK' -ContentType 'application/json; charset=utf-8' -Body $result.Body -AdditionalHeaders @{ 'Cache-Control' = 'no-store' }
    } catch {
        try {
            if ($stream -and $stream.CanWrite) {
                Write-JsonError -Stream $stream -StatusCode 500 -Reason 'Internal Server Error' -Code 'local-server-error' -Message 'The local proxy encountered an unexpected error.'
            }
        } catch { }
    } finally {
        if ($stream) { $stream.Dispose() }
        $Client.Dispose()
    }
}

$listener = $null
$SelectedPort = $null
$pool = $null
$workers = [System.Collections.ArrayList]::new()

try {
    $startupFailures = [System.Collections.Generic.List[string]]::new()
    foreach ($candidatePort in $CandidatePorts) {
        $candidateListener = [System.Net.Sockets.TcpListener]::new($BindAddress, $candidatePort)
        try {
            $candidateListener.Start()
            $listener = $candidateListener
            $SelectedPort = $candidatePort
            break
        } catch [System.Net.Sockets.SocketException] {
            $nativeCode = $_.Exception.NativeErrorCode
            if ($_.Exception.SocketErrorCode -eq [System.Net.Sockets.SocketError]::AddressAlreadyInUse -or $nativeCode -eq 10048) {
                $startupFailures.Add("Port $candidatePort is occupied (AddressAlreadyInUse / WSAEADDRINUSE 10048).")
            } elseif ($_.Exception.SocketErrorCode -eq [System.Net.Sockets.SocketError]::AccessDenied -or $nativeCode -eq 10013) {
                $startupFailures.Add("Port $candidatePort was blocked or reserved by Windows (WSAEACCES 10013).")
            } else {
                $startupFailures.Add("Port $candidatePort could not be opened: $($_.Exception.Message)")
            }
            $candidateListener.Stop()
        }
    }

    if (-not $listener) {
        Write-Host 'Cannot start LogRhythm Log Source Explorer (Unofficial Utility) on any preferred loopback port.' -ForegroundColor Red
        foreach ($failure in $startupFailures) {
            Write-Host " - $failure" -ForegroundColor Red
        }
        Write-Host 'Close the application using these ports, or ask your Windows administrator to release the reservation, then try again.' -ForegroundColor Yellow
        exit 1
    }

    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, 16)
    $pool.Open()

    $BrowserUrl = "http://localhost:$SelectedPort"
    Write-Host 'LogRhythm Log Source Explorer (Unofficial Utility) is running.' -ForegroundColor Green
    Write-Host 'This is an independent community utility and is not an official LogRhythm product.'
    Write-Host "Open: $BrowserUrl"
    Write-Host "The server is bound only to 127.0.0.1:$SelectedPort. Press Ctrl+C to stop."
    try {
        Start-Process $BrowserUrl
    } catch {
        Write-Warning "The browser could not be opened automatically. Open $BrowserUrl manually."
    }

    while ($true) {
        for ($index = $workers.Count - 1; $index -ge 0; $index--) {
            $worker = $workers[$index]
            if ($worker.Handle.IsCompleted) {
                try { $null = $worker.PowerShell.EndInvoke($worker.Handle) } catch { }
                $worker.PowerShell.Dispose()
                $workers.RemoveAt($index)
            }
        }

        if ($listener.Pending()) {
            $client = $listener.AcceptTcpClient()
            $powerShell = [System.Management.Automation.PowerShell]::Create()
            $powerShell.RunspacePool = $pool
            $null = $powerShell.AddScript($ClientHandler.ToString()).AddArgument($client).AddArgument($RootDirectory).AddArgument($SelectedPort)
            $handle = $powerShell.BeginInvoke()
            $null = $workers.Add([pscustomobject]@{ PowerShell = $powerShell; Handle = $handle })
        } else {
            Start-Sleep -Milliseconds 25
        }
    }
} catch [System.Management.Automation.PipelineStoppedException] {
    # Ctrl+C stops the pipeline; cleanup is handled below.
} finally {
    if ($listener) { $listener.Stop() }
    foreach ($worker in $workers) {
        try { $worker.PowerShell.Stop() } catch { }
        try { $null = $worker.PowerShell.EndInvoke($worker.Handle) } catch { }
        $worker.PowerShell.Dispose()
    }
    if ($pool) {
        $pool.Close()
        $pool.Dispose()
    }
    Write-Host "`nLogRhythm Log Source Explorer (Unofficial Utility) stopped."
}
