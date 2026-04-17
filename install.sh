#!/usr/bin/env bash
set -e

echo "====================================="
echo " ThreatMap Infra Installer"
echo "====================================="

# -------------------------------
# System dependencies
# -------------------------------
echo "[*] Installing system dependencies..."
sudo apt update
sudo apt install -y python3 python3-venv python3-pip \
    nmap nikto gobuster curl sslscan 

# -------------------------------
# Create virtual environment
# -------------------------------
echo "[*] Setting up Python environment..."
python3 -m venv .venv
source .venv/bin/activate

pip install --upgrade pip

# -------------------------------
# Python dependencies
# -------------------------------
echo "[*] Installing Python dependencies..."
pip install -r requirements.txt

# -------------------------------
# AI dependencies (MANDATORY)
# -------------------------------
echo "[*] Installing AI dependencies..."
pip install llama-cpp-python huggingface_hub

# -------------------------------
# Download SLM model (AUTO)
# -------------------------------
echo "[*] Setting up AI model (one-time download)..."
python core/setup_slm.py || echo "[!] SLM setup skipped (can retry later)"

echo ""

echo ""
echo "Select report format support:"
echo "1) HTML (Recommended)"
echo "2) HTML + Excel (LibreOffice required)"
read -p "Choice [1/2]: " choice

if [ "$choice" = "2" ]; then
    echo "[*] Installing LibreOffice..."
    sudo apt install -y libreoffice-calc
fi

echo "[✔] Installation complete!"
echo "Run the tool using: ./ThreatMap-Infra"
echo ""
