# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in ThreatIntel-GPT, please report it responsibly.

### How to Report

1. **Do NOT** open a public issue
2. Email security concerns to: contact@ayinedjimi-consultants.fr
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### Response Time

- Initial response: Within 48 hours
- Status update: Within 7 days
- Fix timeline: Depends on severity (Critical: <7 days, High: <14 days, Medium: <30 days)

### Security Best Practices

When using ThreatIntel-GPT:

1. **API Keys**: Never commit API keys to version control
2. **Environment Variables**: Use `.env` files for sensitive configuration
3. **Network Security**: Run API behind firewall/reverse proxy
4. **Authentication**: Implement authentication for production deployments
5. **Rate Limiting**: Configure rate limits to prevent abuse
6. **Input Validation**: The tool validates inputs, but additional validation is recommended
7. **Logging**: Review logs regularly for suspicious activity
8. **Updates**: Keep dependencies updated

### Disclosure Policy

- Security vulnerabilities will be disclosed after a fix is released
- Credit will be given to reporters (unless anonymity is requested)
- A security advisory will be published for critical vulnerabilities

## Security Features

ThreatIntel-GPT includes:
- Input sanitization and validation
- Secure API communication
- No storage of sensitive data by default
- Configurable caching with TTL
- Error handling to prevent information leakage

## Contact

For security inquiries: contact@ayinedjimi-consultants.fr

Author: Ayi NEDJIMI
Website: https://ayinedjimi-consultants.fr
