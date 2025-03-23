# Usage Guide

## Starting a Security Assessment

1. Ensure you have written permission (store in `/var/wifi_security_audit/auth/`)
2. Place a handshake file in the directory `/var/wifi_security_audit/handshakes`
3. The service checks the authorization and begins the analysis
4. After completion of the analysis or timeout (1 hour), a report is sent via email
5. All activities are logged for audit purposes

## Security Audit Tool Parameters

```
security_audit_tool.py [OPTIONS]

Options:
  --daemon        Run as a daemon in the background
  --config        Path to configuration file (default: /etc/wifi_security_audit/config.ini)
  --pid-file      Path to PID file (default: /var/run/wifi_security_audit.pid)
  --educational   Activate educational mode with detailed analysis reports
```

## Generating a Dictionary

The dictionary generator can create customized wordlists for security assessments:

```bash
sudo python3 /usr/local/bin/dictionary_generator.py [OPTIONS]
```

### Dictionary Generator Parameters

```
dictionary_generator.py [OPTIONS]

Options:
  -o, --output         Output file for the word list (default: /var/wifi_security_audit/wordlist.txt)
  --min-length         Minimum password length (default: 8)
  --max-length         Maximum password length (default: 10)
  --lowercase          Include lowercase letters (default: enabled)
  --uppercase          Include uppercase letters
  --digits             Include digits (default: enabled)
  --special            Include special characters
  --no-lowercase       Exclude lowercase letters
  --no-digits          Exclude digits
  --base-words         File with base words to include
  --no-patterns        Disable generation of common patterns with base words
```

### Dictionary Strategies

The dictionary generator can create various combinations:

1. **Character Sets**:
   - Lowercase: a-z
   - Uppercase: A-Z
   - Digits: 0-9
   - Special characters: !@#$%^&*()_+ etc.

2. **Combination with Base Words**:
   - Pure dictionary entries
   - Words + years (1990-2029)
   - Words + common suffixes (123, !, #, etc.)
   - Words with capitalization of the first letter

## Supported Handshake Formats

The system supports the following handshake file formats:

- `.cap` - Main format from Aircrack-ng
- `.pcap` - Standard packet capture format
- `.pcapng` - Next-generation packet capture format
- `.hccapx` - Hashcat format

The system automatically converts between formats for optimal analysis.

## Audit Logging

All activities of this tool are extensively logged to ensure transparency and prevent misuse. The logs contain:
- Timestamps for all actions
- User identification
- Analyzed SSIDs and MAC addresses
- Used authorization documents
- Success or failure of security assessments

These logs can be used for compliance evidence and to document authorized penetration tests.