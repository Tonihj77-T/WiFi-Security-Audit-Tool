#!/bin/bash
# Installation script for WiFi Handshake Cracker

set -e  # Exit on error

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root" 
    exit 1
fi

echo "Installing WiFi Handshake Cracker..."

# Install dependencies
echo "Installing dependencies..."
apt-get update
apt-get install -y python3 python3-pip aircrack-ng hashcat

# Install Python dependencies
echo "Installing Python packages..."
pip3 install python-daemon lockfile tqdm

# Create directories
echo "Creating directories..."
mkdir -p /etc/handshake_cracker
mkdir -p /var/handshake_cracker/handshakes
mkdir -p /var/log/handshake_cracker

# Copy files
echo "Copying files..."
cp handshake_cracker.py /usr/local/bin/
cp wordlist_generator.py /usr/local/bin/
cp handshake_cracker.service /etc/systemd/system/

# Set executable permissions
chmod +x /usr/local/bin/handshake_cracker.py
chmod +x /usr/local/bin/wordlist_generator.py

# Create default config file if it doesn't exist
if [ ! -f /etc/handshake_cracker/config.ini ]; then
    echo "Creating default configuration..."
    cat > /etc/handshake_cracker/config.ini << EOF
[Directories]
monitor_dir = /var/handshake_cracker/handshakes
wordlist_path = /var/handshake_cracker/wordlist.txt

[Email]
sender = sender@gmx.de
password = your_password
recipient = recipient@example.com
server = mail.gmx.net
port = 587
EOF
    echo "IMPORTANT: Please edit /etc/handshake_cracker/config.ini with your email settings."
fi

# Enable and start service
echo "Enabling and starting service..."
systemctl daemon-reload
systemctl enable handshake_cracker.service
systemctl start handshake_cracker.service

# Generate a sample wordlist
echo "Generating a sample wordlist..."
python3 /usr/local/bin/wordlist_generator.py --min-length 6 --max-length 8 --digits --lowercase

echo "Installation complete! The service is now running."
echo ""
echo "Usage:"
echo "- Place WiFi handshake files in /var/handshake_cracker/handshakes"
echo "- Create custom wordlists with: wordlist_generator.py [options]"
echo "- Check service status with: systemctl status handshake_cracker"
echo "- View logs with: tail -f /var/log/handshake_cracker.log"
echo ""
echo "Don't forget to update your email settings in /etc/handshake_cracker/config.ini"
