#!/usr/bin/env bash
# ==============================================================================
# Aegis-SRE: Cloudflare Quick Tunnel Launcher (100% Free - No Account Required)
# ==============================================================================
# Generates an instant public HTTPS URL (e.g. https://xxxx.trycloudflare.com)
# for your local Aegis-SRE Mission Control Dashboard without exposing router ports.

set -e

echo -e "\033[0;36m==================================================================\033[0m"
echo -e "\033[0;32m🛡️  Aegis-SRE Cloudflare Zero-Trust Public Tunnel\033[0m"
echo -e "\033[0;36m==================================================================\033[0m"

if ! command -v cloudflared &> /dev/null; then
    echo -e "\033[0;31m❌ 'cloudflared' not found in PATH.\033[0m"
    echo -e "\033[0;33mPlease install cloudflared:\033[0m"
    echo "  Ubuntu/Debian: curl -L --output cloudflared.deb https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb && sudo dpkg -i cloudflared.deb"
    echo "  macOS: brew install cloudflared"
    exit 1
fi

echo -e "\033[0;32m🚀 Launching free Cloudflare Tunnel targeting http://localhost:8000...\033[0m"
echo -e "\033[0;33m👉 Look for the 'https://xxxx.trycloudflare.com' link in the output below.\033[0m"
echo "Press Ctrl+C to close the tunnel anytime."
echo ""

cloudflared tunnel --url http://localhost:8000
