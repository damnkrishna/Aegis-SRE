# ==============================================================================
# Aegis-SRE: Cloudflare Quick Tunnel Launcher (100% Free - No Account Required)
# ==============================================================================
# Generates an instant public HTTPS URL (e.g. https://xxxx.trycloudflare.com)
# for your local Aegis-SRE Mission Control Dashboard without exposing router ports.

Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "🛡️  Aegis-SRE Cloudflare Zero-Trust Public Tunnel" -ForegroundColor Green
Write-Host "==================================================================" -ForegroundColor Cyan

# Check if cloudflared is installed
if (-not (Get-Command cloudflared -ErrorAction SilentlyContinue)) {
    Write-Host "❌ 'cloudflared' was not found in PATH." -ForegroundColor Red
    Write-Host "Installing cloudflared via winget..." -ForegroundColor Yellow
    winget install --id Cloudflare.cloudflared -e --accept-package-agreements --accept-source-agreements
    
    if (-not (Get-Command cloudflared -ErrorAction SilentlyContinue)) {
        Write-Host "Please restart PowerShell or download manually from: https://github.com/cloudflare/cloudflared/releases/latest" -ForegroundColor Red
        exit 1
    }
}

Write-Host "🚀 Launching free Cloudflare Tunnel targeting http://localhost:8000..." -ForegroundColor Green
Write-Host "👉 Look for the 'https://xxxx.trycloudflare.com' link in the output below." -ForegroundColor Yellow
Write-Host "Press Ctrl+C to close the tunnel anytime.`n" -ForegroundColor Gray

cloudflared tunnel --url http://localhost:8000
