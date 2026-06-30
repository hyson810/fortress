try {
    $r = Invoke-WebRequest -Uri "https://github.com/gorilla/websocket" -UseBasicParsing -TimeoutSec 15 -SkipCertificateCheck
    Write-Host "SUCCESS: $($r.StatusCode)"
} catch {
    Write-Host "FAILED: $($_.Exception.Message)"
}
