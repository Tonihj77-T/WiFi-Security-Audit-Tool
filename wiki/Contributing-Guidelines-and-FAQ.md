# Contributing Guidelines and FAQ

## Contributing

If you wish to contribute to this project:

1. **Fork the repository**:
   - Create your own copy of the project on GitHub

2. **Create a feature branch**:
   - Make a branch with a descriptive name related to your changes
   - Example: `git checkout -b feature/improved-dictionary-generator`

3. **Implement your changes**:
   - Follow the existing code style and patterns
   - Maintain the ethical focus of the project
   - Add appropriate comments and documentation

4. **Add comprehensive tests**:
   - Write tests for new functionality
   - Ensure existing tests still pass

5. **Submit a pull request**:
   - Provide a clear description of the changes
   - Reference any relevant issues
   - Explain the benefits of your changes

All contributions must adhere to the ethical guidelines of this project and maintain the focus on legitimate security assessment.

## Code Style Guidelines

When contributing code, please follow these guidelines:

1. **Python Code**:
   - Follow PEP 8 style guidelines
   - Use meaningful variable and function names
   - Add docstrings for all functions and classes
   - Keep functions focused on a single responsibility

2. **Shell Scripts**:
   - Include appropriate shebang lines
   - Add comments for complex operations
   - Test on multiple distributions if possible

3. **Documentation**:
   - Keep documentation in sync with code changes
   - Use clear, concise language
   - Include examples where helpful

## Frequently Asked Questions (FAQ)

### General Questions

**Q: What is the purpose of this tool?**  
A: This tool is designed for legitimate WiFi security assessment to help identify vulnerabilities in your own networks or networks you have explicit permission to test.

**Q: Is this tool legal to use?**  
A: The tool itself is legal, but how you use it matters. It's legal when used on your own networks or with explicit written permission. Unauthorized use on others' networks is illegal in most jurisdictions.

**Q: Do I need special hardware to use this tool?**  
A: While the tool itself doesn't require special hardware, capturing handshake files typically requires a WiFi adapter capable of monitor mode.

### Technical Questions

**Q: How long does the analysis process take?**  
A: Analysis time varies based on several factors: the complexity of the password, the size of your wordlist, and your system's performance. Simple analyses might take minutes, while complex ones could take hours.

**Q: What's the difference between educational mode and regular mode?**  
A: Educational mode provides more detailed information in the reports, including explanations of WiFi security concepts and how different attack vectors work. It's designed for learning purposes.

**Q: Can this tool crack all WiFi passwords?**  
A: No. The tool can only identify passwords that are present in the wordlist you provide. Strong, unique passwords that aren't in common wordlists won't be found.

**Q: Which WiFi security protocols can be analyzed?**  
A: The tool primarily works with WPA and WPA2 handshakes. WEP is also supported but is rarely used nowadays. WPA3 has significantly improved security and is much more resistant to these types of analyses.

### Installation and Configuration

**Q: Why do I need to configure email settings?**  
A: Email settings allow the tool to send you security assessment reports once analysis is complete, which is especially useful when running the service in the background.

**Q: Can I use providers other than GMX for email notifications?**  
A: Yes, you can use any email provider that offers SMTP access. Just update the server and port settings in the configuration file accordingly.

**Q: How do I create a custom wordlist?**  
A: Use the dictionary_generator.py tool with your preferred parameters. For example:
```bash
sudo python3 /usr/local/bin/dictionary_generator.py --min-length 8 --max-length 12 --uppercase --digits --special
```

**Q: Where should I store authorization documents?**  
A: Store them in the `/var/wifi_security_audit/auth/` directory with a `.auth` extension. Each document should clearly specify the networks you're authorized to test.