# Installation and Configuration

## Quick Installation

```bash
sudo ./install.sh
```

The installation script:
1. Installs all required dependencies
2. Sets up directory structure with appropriate permissions
3. Creates configuration templates
4. Generates authorization document templates
5. Sets up the systemd service for automated operation

After installation:
1. Edit the configuration file: `/etc/wifi_security_audit/config.ini`
2. Update the email settings (GMX credentials)
3. Optional: Create a custom dictionary
4. Add the required authorization documentation

## Configuration

The configuration file is located at `/etc/wifi_security_audit/config.ini`:

```ini
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
```

## Service Management

```bash
# Check status
sudo systemctl status wifi_security_audit.service

# Start service
sudo systemctl start wifi_security_audit.service

# Stop service
sudo systemctl stop wifi_security_audit.service

# Restart service
sudo systemctl restart wifi_security_audit.service

# View logs
sudo tail -f /var/log/wifi_security_audit.log
```

## Dependencies

The installation script automatically installs:
- Python 3
- Aircrack-ng
- Hashcat
- Python packages: python-daemon, lockfile, tqdm

## Directory Structure

```
/etc/wifi_security_audit/config.ini   - Configuration file
/usr/local/bin/security_audit_tool.py - Main program
/usr/local/bin/dictionary_generator.py - Dictionary generator
/var/wifi_security_audit/handshakes/  - Directory for handshake files
/var/wifi_security_audit/auth/        - Directory for authorization files
/var/wifi_security_audit/wordlist.txt - Default dictionary
/var/log/wifi_security_audit.log      - Log file
/var/run/wifi_security_audit.pid      - PID file
```