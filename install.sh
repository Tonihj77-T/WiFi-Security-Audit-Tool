#!/bin/bash
# Installation script for WiFi Security Audit Tool

set -e  # Exit on error

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root" 
    exit 1
fi

echo "Installing WiFi Security Audit Tool..."
echo "This tool is intended for legitimate security assessment with proper authorization."

# Disclaimer
echo ""
echo "====================================================================="
echo "IMPORTANT LEGAL NOTICE"
echo "====================================================================="
echo "This tool is provided for legitimate security auditing purposes only."
echo "Using this tool to access networks without authorization is illegal."
echo ""
echo "By proceeding with installation, you agree to use this tool only for:"
echo "1. Security assessments of your own networks"
echo "2. Networks where you have explicit written permission"
echo "3. Educational purposes in controlled environments"
echo "====================================================================="
echo ""

read -p "Do you understand and agree to these terms? (y/n): " confirm
if [[ $confirm != "y" && $confirm != "Y" ]]; then
    echo "Installation cancelled."
    exit 1
fi

# Install dependencies
echo "Installing dependencies..."
apt-get update
apt-get install -y python3 python3-pip aircrack-ng hashcat

# Install Python dependencies
echo "Installing Python packages..."
pip3 install python-daemon lockfile tqdm

# Create directories
echo "Creating directories..."
mkdir -p /etc/wifi_security_audit
mkdir -p /var/wifi_security_audit/handshakes
mkdir -p /var/wifi_security_audit/auth
mkdir -p /var/log/wifi_security_audit

# Copy files
echo "Copying files..."
cp security_audit_tool.py /usr/local/bin/
cp dictionary_generator.py /usr/local/bin/
cp wifi_security_audit.service /etc/systemd/system/

# Set executable permissions
chmod +x /usr/local/bin/security_audit_tool.py
chmod +x /usr/local/bin/dictionary_generator.py

# Create default config file if it doesn't exist
if [ ! -f /etc/wifi_security_audit/config.ini ]; then
    echo "Creating default configuration..."
    cat > /etc/wifi_security_audit/config.ini << EOF
[Directories]
monitor_dir = /var/wifi_security_audit/handshakes
wordlist_path = /var/wifi_security_audit/wordlist.txt
auth_dir = /var/wifi_security_audit/auth

[Email]
sender = sender@gmx.de
password = your_password
recipient = recipient@example.com
server = mail.gmx.net
port = 587

[Security]
require_authorization = true
audit_logging = true
local_network_only = true
EOF
    echo "IMPORTANT: Please edit /etc/wifi_security_audit/config.ini with your email settings."
fi

# Create authorization template
echo "Creating authorization template document..."
cat > /var/wifi_security_audit/auth/authorization_template.txt << EOF
WIFI SECURITY ASSESSMENT AUTHORIZATION

I, [FULL NAME], the owner or authorized administrator of the WiFi network(s) 
listed below, hereby grant permission to conduct security assessments on these networks:

Network SSID: [NETWORK NAME]
MAC Address: [NETWORK MAC ADDRESS, IF KNOWN]
Location: [PHYSICAL LOCATION]

Authorization Period: [START DATE] to [END DATE]

This authorization is granted for the purpose of:
[ ] Vulnerability assessment
[ ] Security audit
[ ] Educational demonstration
[ ] Other: ___________________________

The authorization is granted to:
Name: [AUDITOR NAME]
Organization: [ORGANIZATION, IF APPLICABLE]
Contact: [EMAIL/PHONE]

By signing below, I confirm that I have the legal authority to grant this permission.

Signature: _________________________
Date: _____________________________

Please save this document as [NETWORK_NAME].auth in the /var/wifi_security_audit/auth/ directory.
EOF

chmod 600 /var/wifi_security_audit/auth/authorization_template.txt
echo "Authorization template created at /var/wifi_security_audit/auth/authorization_template.txt"

# Enable and start service
echo "Enabling and starting service..."
systemctl daemon-reload
systemctl enable wifi_security_audit.service
systemctl start wifi_security_audit.service

# Generate a sample wordlist
echo "Generating a sample dictionary..."
python3 /usr/local/bin/dictionary_generator.py --min-length 6 --max-length 8 --digits --lowercase

echo "Installation complete! The service is now running."
echo ""
echo "IMPORTANT: Before using this tool for security assessment:"
echo "1. Complete the authorization template in /var/wifi_security_audit/auth/"
echo "2. Save a completed authorization document for each network"
echo "3. Update your email settings in /etc/wifi_security_audit/config.ini"
echo ""
echo "Usage:"
echo "- Place WiFi handshake files in /var/wifi_security_audit/handshakes"
echo "- Create custom dictionaries with: dictionary_generator.py [options]"
echo "- Check service status with: systemctl status wifi_security_audit"
echo "- View logs with: tail -f /var/log/wifi_security_audit.log"
echo ""
echo "Remember: This tool must only be used for authorized security assessments."
