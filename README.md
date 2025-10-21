# OWASP Top 10 2021 - Educational Examples

This repository contains educational examples demonstrating the OWASP Top 10 2021 security vulnerabilities. Each directory contains intentionally vulnerable code for learning purposes.

## ⚠️ WARNING
**These examples contain intentional security vulnerabilities and should NEVER be used in production environments!**

## OWASP Top 10 2021 Examples

### A01: Broken Access Control
- **Directory**: `A01/`
- **Description**: Missing or improper access controls allowing unauthorized access to resources
- **Example**: User privilege escalation and unauthorized data access

### A02: Cryptographic Failures  
- **Directory**: `A02/`
- **Description**: Failures related to cryptography leading to sensitive data exposure
- **Examples**: Weak password hashing (MD5), inadequate encryption (XOR), insecure communication

### A03: Injection
- **Directory**: `A03/`
- **Description**: SQL injection vulnerabilities in database queries
- **Example**: Flask REST API with SQLite demonstrating SQL injection attacks

### A04: Insecure Design
- **Directory**: `A04/`
- **Description**: Design flaws that lead to security vulnerabilities
- **Example**: Fund transfer system without proper authorization checks

### A05: Security Misconfiguration
- **Directory**: `A05/`
- **Description**: Insecure default configurations and exposed sensitive information
- **Examples**: Debug mode enabled, weak secret keys, configuration exposure

### A06: Vulnerable and Outdated Components
- **Directory**: `A06/`
- **Description**: Using components with known security vulnerabilities
- **Examples**: Outdated packages, vulnerable XML parsing, disabled SSL verification

### A07: Identification and Authentication Failures
- **Directory**: `A07/`
- **Description**: Broken authentication mechanisms and weak password policies
- **Examples**: Weak passwords, no rate limiting, predictable password resets

### A08: Software and Data Integrity Failures
- **Directory**: `A08/`
- **Description**: Code and infrastructure that don't protect against integrity violations
- **Examples**: Unverified software updates, unsafe deserialization, missing checksums

### A09: Security Logging and Monitoring Failures
- **Directory**: `A09/`
- **Description**: Insufficient logging and monitoring of security events
- **Examples**: No login attempt logging, missing audit trails, unlogged critical actions

### A10: Server-Side Request Forgery (SSRF)
- **Directory**: `A10/`
- **Description**: Fetching remote resources without validating user-supplied URLs
- **Examples**: Unvalidated URL fetching, webhook callbacks, proxy services

## How to Use

1. **Study the Code**: Each directory contains vulnerable implementations
2. **Read the Comments**: Code includes comments explaining the "business logic"
3. **Identify Vulnerabilities**: Try to spot the security issues
4. **Check Solutions**: Most directories include README files with explanations and secure alternatives
5. **Test Safely**: Run examples only in isolated, controlled environments

## Running the Examples

Most examples are Flask applications. To run them:

```bash
cd A0X/  # Replace X with the number
pip install flask requests  # Install dependencies
python A0X_Example_*.py     # Run the application
```

## Educational Purpose

These examples are designed for:
- Security training and education
- Understanding common vulnerability patterns  
- Learning secure coding practices
- Demonstrating attack vectors in controlled environments

## References

- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/)

## Disclaimer

This code is for educational purposes only. The authors are not responsible for any misuse of this code. Always follow responsible disclosure practices and only test on systems you own or have explicit permission to test.

---
**Remember: Never use these vulnerable patterns in production code!**
