#!/usr/bin/env python3
"""
WiFi Security Audit Tool - Monitors a directory for handshake files,
analyzes them for security assessment, and sends the results via email.

This tool is intended for legitimate security auditing of WiFi networks with proper authorization.
"""

import os
import time
import subprocess
import logging
import smtplib
import tempfile
import shutil
import datetime
import socket
import getpass
import ipaddress
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import re
import sys
import argparse
from pathlib import Path
import configparser
import signal
import daemon
from lockfile.pidlockfile import PIDLockFile

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("/var/log/wifi_security_audit.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("wifi_security_audit")

class SecurityAuditTool:
    def __init__(self, config_path="/etc/wifi_security_audit/config.ini", educational_mode=False):
        """Initialize the SecurityAuditTool with configuration."""
        self.config = self._load_config(config_path)
        self.monitor_dir = self.config.get('Directories', 'monitor_dir')
        self.wordlist_path = self.config.get('Directories', 'wordlist_path')
        self.auth_dir = self.config.get('Directories', 'auth_dir', fallback='/var/wifi_security_audit/auth')
        self.temp_dir = tempfile.mkdtemp()
        self.timeout = 3600  # 1 hour in seconds
        self.educational_mode = educational_mode
        
        # Security settings
        self.require_authorization = self.config.getboolean('Security', 'require_authorization', fallback=True)
        self.audit_logging = self.config.getboolean('Security', 'audit_logging', fallback=True)
        self.local_network_only = self.config.getboolean('Security', 'local_network_only', fallback=True)
        
        # Email settings
        self.email_sender = self.config.get('Email', 'sender')
        self.email_password = self.config.get('Email', 'password')
        self.email_recipient = self.config.get('Email', 'recipient')
        self.email_server = self.config.get('Email', 'server')
        self.email_port = self.config.getint('Email', 'port')
        
        # Ensure required tools are installed
        self._check_dependencies()
        
        # Ensure the required directories exist
        os.makedirs(self.monitor_dir, exist_ok=True)
        os.makedirs(self.auth_dir, exist_ok=True)
        
        # Initialize audit log
        self.audit_log = []
        
        logger.info(f"SecurityAuditTool initialized. Monitoring directory: {self.monitor_dir}")
        self._log_audit_event("SYSTEM_INIT", "Security Audit Tool initialized")

    def _load_config(self, config_path):
        """Load configuration from file."""
        config = configparser.ConfigParser()
        
        # Default configuration
        config['Directories'] = {
            'monitor_dir': '/var/wifi_security_audit/handshakes',
            'wordlist_path': '/var/wifi_security_audit/wordlist.txt',
            'auth_dir': '/var/wifi_security_audit/auth'
        }
        
        config['Email'] = {
            'sender': 'sender@gmx.de',
            'password': 'your_password',
            'recipient': 'recipient@example.com',
            'server': 'mail.gmx.net',
            'port': '587'
        }
        
        config['Security'] = {
            'require_authorization': 'true',
            'audit_logging': 'true',
            'local_network_only': 'true'
        }
        
        # Create config directory if it doesn't exist
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        
        # Read config file if it exists
        if os.path.exists(config_path):
            config.read(config_path)
        else:
            # Create default config file
            with open(config_path, 'w') as configfile:
                config.write(configfile)
            logger.info(f"Created default configuration file at {config_path}")
            
        return config

    def _check_dependencies(self):
        """Check and install required dependencies."""
        dependencies = ['aircrack-ng', 'hashcat']
        
        for dep in dependencies:
            try:
                subprocess.run(['which', dep], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                logger.info(f"{dep} is already installed.")
            except subprocess.CalledProcessError:
                logger.info(f"{dep} not found. Installing...")
                try:
                    subprocess.run(['apt-get', 'update'], check=True)
                    subprocess.run(['apt-get', 'install', '-y', dep], check=True)
                    logger.info(f"{dep} installed successfully.")
                except subprocess.CalledProcessError:
                    logger.error(f"Failed to install {dep}. Please install it manually.")
                    sys.exit(1)

    def _log_audit_event(self, event_type, description, ssid=None, mac=None, result=None):
        """Log an audit event with detailed information."""
        if not self.audit_logging:
            return
            
        timestamp = datetime.datetime.now().isoformat()
        username = getpass.getuser()
        hostname = socket.gethostname()
        
        audit_entry = {
            "timestamp": timestamp,
            "user": username,
            "hostname": hostname,
            "event_type": event_type,
            "description": description,
            "ssid": ssid,
            "mac_address": mac,
            "result": result
        }
        
        self.audit_log.append(audit_entry)
        
        # Write to the audit log file
        with open("/var/log/wifi_security_audit_events.log", "a") as f:
            f.write(f"{timestamp} | {username}@{hostname} | {event_type} | {description} | " +
                   f"SSID:{ssid or 'N/A'} | MAC:{mac or 'N/A'} | Result:{result or 'N/A'}\n")

    def _check_authorization(self, file_path):
        """Check if there is a valid authorization for the network."""
        if not self.require_authorization:
            return True
            
        # Extract SSID and MAC address
        ssid = self._extract_ssid(file_path)
        mac = self._extract_mac(file_path)
        
        # Look for authorization files
        auth_found = False
        auth_file = None
        
        # Check for ssid-specific authorization
        for filename in os.listdir(self.auth_dir):
            if filename.lower().endswith('.auth'):
                auth_file_path = os.path.join(self.auth_dir, filename)
                with open(auth_file_path, 'r') as f:
                    content = f.read()
                    if ssid.lower() in content.lower() or (mac and mac.lower() in content.lower()):
                        auth_found = True
                        auth_file = auth_file_path
                        break
        
        if auth_found:
            logger.info(f"Authorization found for SSID: {ssid}")
            self._log_audit_event("AUTHORIZATION_VALID", "Valid authorization found", ssid, mac, "AUTHORIZED")
            return True
        else:
            logger.warning(f"No authorization found for SSID: {ssid}. Analysis aborted.")
            self._log_audit_event("AUTHORIZATION_MISSING", "No valid authorization found", ssid, mac, "UNAUTHORIZED")
            return False

    def _check_local_network(self, file_path):
        """Check if the network is in the local network range."""
        if not self.local_network_only:
            return True
            
        # Get local network information
        local_ips = []
        try:
            # Get all local IP addresses
            hostname = socket.gethostname()
            local_ips = [ip for ip in socket.gethostbyname_ex(hostname)[2] if not ip.startswith("127.")]
            
            # If no non-localhost IPs found, use a common private network range check
            if not local_ips:
                ssid = self._extract_ssid(file_path)
                # Common SSIDs for local networks
                local_prefixes = ["home", "private", "linksys", "netgear", "tp-link", "fritz", "asus", "dlink"]
                
                if any(prefix in ssid.lower() for prefix in local_prefixes):
                    logger.info(f"SSID '{ssid}' appears to be a local network based on name.")
                    return True
                    
                logger.warning(f"Could not verify if '{ssid}' is a local network. Additional authorization required.")
                return False
                
            # If we have local IPs, we'll assume it's allowed if authorization exists
            return True
            
        except Exception as e:
            logger.error(f"Error checking local network: {str(e)}")
            return False

    def _detect_file_type(self, file_path):
        """Detect the type of handshake file and convert if necessary."""
        file_extension = os.path.splitext(file_path)[1].lower()
        converted_path = None
        
        if file_extension in ['.cap', '.pcap', '.pcapng']:
            # Convert to hccapx for hashcat
            converted_path = os.path.join(self.temp_dir, "converted.hccapx")
            try:
                subprocess.run(
                    ['cap2hccapx', file_path, converted_path],
                    check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
                return 'hashcat', converted_path
            except subprocess.CalledProcessError:
                logger.warning("Failed to convert to hccapx. Trying aircrack-ng instead.")
                return 'aircrack-ng', file_path
        else:
            # If unknown extension, try both tools
            return 'aircrack-ng', file_path
            
    def _extract_ssid(self, file_path):
        """Extract SSID from handshake file."""
        try:
            output = subprocess.run(
                ['aircrack-ng', file_path],
                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30
            )
            
            # Extract SSID from aircrack-ng output
            ssid_match = re.search(r'SSID:\s+([^\n]+)', output.stdout)
            if ssid_match:
                return ssid_match.group(1).strip()
            else:
                logger.warning("Could not extract SSID from file.")
                return "Unknown SSID"
                
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            logger.warning("Failed to extract SSID. Using filename instead.")
            return os.path.basename(file_path)

    def _extract_mac(self, file_path):
        """Extract MAC address from handshake file."""
        try:
            output = subprocess.run(
                ['aircrack-ng', file_path],
                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30
            )
            
            # Extract BSSID (MAC) from aircrack-ng output
            mac_match = re.search(r'BSSID:\s+([0-9A-F:]{17})', output.stdout, re.IGNORECASE)
            if mac_match:
                return mac_match.group(1).strip()
            else:
                logger.warning("Could not extract MAC address from file.")
                return None
                
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            logger.warning("Failed to extract MAC address.")
            return None

    def _analyze_with_aircrack(self, file_path):
        """Analyze the handshake using aircrack-ng."""
        try:
            output = subprocess.run(
                ['aircrack-ng', '-w', self.wordlist_path, file_path],
                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=self.timeout
            )
            
            # Extract password from aircrack-ng output
            password_match = re.search(r'KEY FOUND!\s*\[\s*([^\]]+)\s*\]', output.stdout)
            if password_match:
                result = password_match.group(1).strip()
                self._log_audit_event("SECURITY_ISSUE_FOUND", "Security vulnerability detected", 
                                    self._extract_ssid(file_path), self._extract_mac(file_path), "WEAK_PASSWORD")
                return result
            else:
                self._log_audit_event("SECURITY_ASSESSMENT", "Security assessment completed", 
                                    self._extract_ssid(file_path), self._extract_mac(file_path), "NO_ISSUES_FOUND")
                return None
                
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            logger.error("Aircrack-ng analysis failed or timed out")
            return None

    def _analyze_with_hashcat(self, file_path):
        """Analyze the handshake using hashcat."""
        output_file = os.path.join(self.temp_dir, "hashcat_output.txt")
        
        try:
            subprocess.run(
                ['hashcat', '-m', '2500', '-a', '0', file_path, self.wordlist_path, '-o', output_file],
                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=self.timeout
            )
            
            # Check if output file exists and contains the password
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    content = f.read().strip()
                    if content:
                        # Extract password from hashcat output
                        password_match = re.search(r':(.*?)$', content)
                        if password_match:
                            result = password_match.group(1).strip()
                            self._log_audit_event("SECURITY_ISSUE_FOUND", "Security vulnerability detected", 
                                                self._extract_ssid(file_path), self._extract_mac(file_path), "WEAK_PASSWORD")
                            return result
            
            self._log_audit_event("SECURITY_ASSESSMENT", "Security assessment completed", 
                                self._extract_ssid(file_path), self._extract_mac(file_path), "NO_ISSUES_FOUND")
            return None
                
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            logger.error("Hashcat analysis failed or timed out")
            return None

    def _generate_security_report(self, ssid, mac, result, analysis_duration):
        """Generate a comprehensive security report."""
        report = []
        report.append(f"SECURITY AUDIT REPORT - {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("=" * 80)
        report.append(f"Network SSID: {ssid}")
        report.append(f"Network MAC Address: {mac or 'Not available'}")
        report.append(f"Analysis Duration: {analysis_duration:.2f} seconds")
        report.append("-" * 80)
        
        if result:
            report.append("SECURITY VULNERABILITY DETECTED")
            report.append(f"The network is using a common or weak password that was detected during analysis.")
            report.append("\nRECOMMENDATIONS:")
            report.append("1. Change the WiFi password immediately to a strong alternative")
            report.append("2. Use a password with at least 12 characters including uppercase, lowercase, numbers, and special characters")
            report.append("3. Consider upgrading to WPA3 if your devices support it")
            report.append("4. Disable WPS (WiFi Protected Setup) as it can be vulnerable to attacks")
        else:
            report.append("NO IMMEDIATE SECURITY ISSUES FOUND")
            report.append("The network password was not found using common wordlists.")
            report.append("\nRECOMMENDATIONS:")
            report.append("1. Continue using strong, unique passwords for your WiFi network")
            report.append("2. Regularly update router firmware to address security vulnerabilities")
            report.append("3. Consider setting up a separate guest network for visitors")
            report.append("4. Implement MAC address filtering for additional security")
        
        report.append("\n" + "-" * 80)
        report.append("Note: This is an automated security assessment. For a comprehensive security evaluation,")
        report.append("consider engaging with a professional IT security consultant.")
        
        if self.educational_mode:
            report.append("\n" + "=" * 80)
            report.append("EDUCATIONAL INFORMATION - HOW WIFI SECURITY WORKS")
            report.append("-" * 80)
            report.append("WiFi networks typically use the following security protocols:")
            report.append("- WEP: Outdated and easily broken, should not be used")
            report.append("- WPA: Improved security over WEP but has known vulnerabilities")
            report.append("- WPA2: Currently the most common protocol, more secure but still vulnerable to certain attacks")
            report.append("- WPA3: The latest standard with improved security features")
            report.append("\nCommon attack vectors include:")
            report.append("1. Dictionary attacks - using common passwords to guess the WiFi password")
            report.append("2. Brute force attacks - trying all possible password combinations")
            report.append("3. WPS attacks - exploiting vulnerabilities in WiFi Protected Setup")
            report.append("\nBest practices for wireless security:")
            report.append("- Use WPA2/WPA3 with AES encryption")
            report.append("- Implement strong, unique passwords (12+ characters)")
            report.append("- Change default router credentials")
            report.append("- Keep router firmware updated")
            report.append("- Use a separate guest network for visitors")
            report.append("- Consider implementing MAC address filtering")
        
        return "\n".join(report)

    def _send_email(self, ssid, result, analysis_duration=None):
        """Send email with the security assessment results."""
        try:
            msg = MIMEMultipart()
            msg['From'] = self.email_sender
            msg['To'] = self.email_recipient
            
            if result:
                msg['Subject'] = f"WiFi Security Alert: {ssid}"
            else:
                msg['Subject'] = f"WiFi Security Report: {ssid}"
            
            mac = self._extract_mac(self.current_file_path) if hasattr(self, 'current_file_path') else None
            body = self._generate_security_report(ssid, mac, result, analysis_duration or 0)
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(self.email_server, self.email_port)
            server.starttls()
            server.login(self.email_sender, self.email_password)
            text = msg.as_string()
            server.sendmail(self.email_sender, self.email_recipient, text)
            server.quit()
            
            logger.info(f"Email sent successfully for SSID: {ssid}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email: {str(e)}")
            return False

    def _process_handshake_file(self, file_path):
        """Process a handshake file for security assessment."""
        logger.info(f"Processing handshake file: {file_path}")
        self.current_file_path = file_path
        
        # Check authorization
        if not self._check_authorization(file_path):
            logger.warning(f"Unauthorized analysis attempt for {file_path}. Skipping.")
            return False
            
        # Check if it's a local network (if enabled)
        if self.local_network_only and not self._check_local_network(file_path):
            logger.warning(f"Non-local network in {file_path}. Additional authorization required.")
            self._log_audit_event("SECURITY_CHECK", "Non-local network requires additional authorization", 
                                 self._extract_ssid(file_path), self._extract_mac(file_path), "BLOCKED")
            return False
        
        # Extract SSID
        ssid = self._extract_ssid(file_path)
        logger.info(f"Analyzing security for SSID: {ssid}")
        
        # Record start time for performance measurement
        start_time = time.time()
        
        # Detect file type and convert if necessary
        tool, analysis_file = self._detect_file_type(file_path)
        logger.info(f"Using {tool} with file {analysis_file}")
        
        # Start security assessment
        self._log_audit_event("SECURITY_ASSESSMENT_START", "Beginning security assessment", 
                             ssid, self._extract_mac(file_path))
        
        # Try to analyze the security
        result = None
        if tool == 'hashcat':
            result = self._analyze_with_hashcat(analysis_file)
            # If hashcat fails, try aircrack-ng
            if result is None:
                result = self._analyze_with_aircrack(file_path)
        else:
            result = self._analyze_with_aircrack(file_path)
            # If aircrack-ng fails, try to convert and use hashcat
            if result is None:
                converted_path = os.path.join(self.temp_dir, "converted.hccapx")
                try:
                    subprocess.run(
                        ['cap2hccapx', file_path, converted_path],
                        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                    )
                    result = self._analyze_with_hashcat(converted_path)
                except subprocess.CalledProcessError:
                    logger.warning("Failed to convert for hashcat attempt")
        
        # Calculate analysis duration
        analysis_duration = time.time() - start_time
        
        # Send email with results
        if result:
            logger.warning(f"Security vulnerability found for {ssid}")
            self._send_email(ssid, result, analysis_duration)
            return True
        else:
            logger.info(f"No immediate security issues found for {ssid}")
            self._send_email(ssid, None, analysis_duration)
            return True

    def monitor_directory(self):
        """Monitor directory for handshake files and process them."""
        logger.info(f"Starting to monitor directory for security assessments: {self.monitor_dir}")
        
        while True:
            try:
                # Check for files in the directory
                for filename in os.listdir(self.monitor_dir):
                    file_path = os.path.join(self.monitor_dir, filename)
                    
                    # Skip directories
                    if os.path.isdir(file_path):
                        continue
                        
                    # Process the file
                    success = self._process_handshake_file(file_path)
                    
                    # Remove the file after processing
                    try:
                        os.remove(file_path)
                        logger.info(f"Removed file after assessment: {file_path}")
                    except OSError as e:
                        logger.error(f"Error removing file {file_path}: {str(e)}")
                
                # Wait 60 seconds before checking again
                time.sleep(60)
                
            except Exception as e:
                logger.error(f"Error in monitor loop: {str(e)}")
                # Continue monitoring despite errors
                time.sleep(60)
                
    def cleanup(self):
        """Clean up temporary files."""
        try:
            shutil.rmtree(self.temp_dir)
            logger.info("Cleaned up temporary directory")
        except OSError as e:
            logger.error(f"Error cleaning up temporary directory: {str(e)}")

def run_as_daemon(pid_file, config_path, educational_mode=False):
    """Run the SecurityAuditTool as a daemon."""
    with daemon.DaemonContext(
        pidfile=PIDLockFile(pid_file),
        signal_map={
            signal.SIGTERM: lambda signum, frame: sys.exit(0),
            signal.SIGINT: lambda signum, frame: sys.exit(0),
        }
    ):
        audit_tool = SecurityAuditTool(config_path, educational_mode)
        try:
            audit_tool.monitor_directory()
        finally:
            audit_tool.cleanup()

def main():
    """Main function to set up and run the SecurityAuditTool."""
    parser = argparse.ArgumentParser(description='WiFi Security Audit Tool')
    parser.add_argument('--daemon', action='store_true', help='Run as a daemon')
    parser.add_argument('--config', default='/etc/wifi_security_audit/config.ini', help='Path to configuration file')
    parser.add_argument('--pid-file', default='/var/run/wifi_security_audit.pid', help='Path to PID file when running as daemon')
    parser.add_argument('--educational', action='store_true', help='Run in educational mode with detailed reports')
    args = parser.parse_args()
    
    if args.daemon:
        run_as_daemon(args.pid_file, args.config, args.educational)
    else:
        audit_tool = SecurityAuditTool(args.config, args.educational)
        try:
            audit_tool.monitor_directory()
        except KeyboardInterrupt:
            logger.info("Stopping security audit tool...")
        finally:
            audit_tool.cleanup()

if __name__ == "__main__":
    print("""
    
    ===================================================================
    WiFi Security Audit Tool - For Educational and Authorized Use Only
    ===================================================================
    
    This tool is intended for legitimate security auditing of WiFi networks 
    with proper authorization. Unauthorized use is illegal and unethical.
    
    Before proceeding, ensure you have:
    1. Written permission from the network owner
    2. Placed the authorization document in the auth directory
    3. Understanding of applicable laws in your jurisdiction
    
    ===================================================================
    """)
    
    consent = input("Do you understand and agree to use this tool only for authorized security assessments? (y/n): ")
    if consent.lower() != 'y':
        print("Exiting. This tool may only be used for authorized security assessments.")
        sys.exit(0)
    
    main()
