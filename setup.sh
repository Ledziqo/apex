#!/bin/bash
# APEX - VPS Setup Script
# Optimized for KVM 1 (1 vCPU, 1 GB RAM)

echo "============================================"
echo "  🔺 APEX - VPS Setup"
echo "  Professional Red Team Framework"
echo "============================================"
echo ""

# Update system
echo "[*] Updating system packages..."
apt-get update -y && apt-get upgrade -y

# Install dependencies
echo "[*] Installing system dependencies..."
apt-get install -y python3 python3-pip python3-venv tor proxychains wireguard git curl wget nmap

# Create swap file (2 GB for KVM 1)
echo "[*] Creating 2 GB swap file..."
if [ ! -f /swapfile ]; then
    fallocate -l 2G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
    echo "Swap file created and enabled."
else
    echo "Swap file already exists."
fi

# Setup Python virtual environment
echo "[*] Setting up Python environment..."
cd /opt/apex 2>/dev/null || cd "$(dirname "$0")"
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
echo "[*] Installing Python packages..."
pip install --upgrade pip
pip install -r requirements.txt

# Create directories
echo "[*] Creating directory structure..."
mkdir -p data/uploads reports payloads

# Configure Tor
echo "[*] Configuring Tor..."
systemctl enable tor
systemctl start tor

# Create proxy list placeholder
echo "# Add your SOCKS5/HTTP proxies here (one per line)" > data/proxies.txt
echo "# Format: socks5://ip:port or http://ip:port" >> data/proxies.txt

# Set permissions
chmod -R 755 .

echo ""
echo "============================================"
echo "  ✅ APEX Setup Complete!"
echo "============================================"
echo ""
echo "  To start APEX:"
echo "    source venv/bin/activate"
echo "    python app.py"
echo ""
echo "  Dashboard: http://YOUR_VPS_IP:5000"
echo "  Login: Apex@gmail.com / Apex2005"
echo ""
echo "  ⚠ Make sure to open port 5000 in your firewall:"
echo "    ufw allow 5000"
echo ""
echo "============================================"