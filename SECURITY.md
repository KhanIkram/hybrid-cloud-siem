# Security Policy

## About This Repository

This is a **portfolio project** demonstrating security engineering skills. It contains:
- Detection queries (SPL)
- Configuration templates
- Python code for MCP integration
- Documentation

## Sanitization

All sensitive information has been removed or replaced:

| Data Type | Treatment |
|-----------|-----------|
| IP addresses | Replaced with RFC 5737 documentation ranges |
| Hostnames | Replaced with generic placeholders |
| API keys | Template files only (`.env.template`) |
| Cloud specifics | Generalized instructions |
| Personal data | Removed entirely |

### RFC 5737 Documentation Addresses

This repository uses the following IP ranges designated for documentation:
- `192.0.2.0/24` (TEST-NET-1)
- `198.51.100.0/24` (TEST-NET-2)
- `203.0.113.0/24` (TEST-NET-3)

These ranges are reserved and will never be routed on the public internet.

## Reporting Security Issues

If you discover sensitive information that should have been redacted:

1. **Do not** open a public issue
2. Contact me directly via [ikramrkhan3@gmail.com or linkedin]
3. I will address it promptly

## Security Considerations for Implementation

If you implement this project yourself, ensure you:

1. **Never commit `.env` files** - Use `.env.template` as reference only
2. **Restrict API access** - Limit Splunk API (8089) to trusted IPs
3. **Use least privilege** - Create read-only Splunk accounts for the MCP server
4. **Rotate credentials** - Don't reuse API keys across environments
5. **Review firewall rules** - Limit inbound to required ports only
6. **Monitor your monitoring** - Implement the pipeline health alerts

## Disclaimer

This project is provided for educational and portfolio purposes. The author is not responsible for:
- Misuse of detection techniques
- Security incidents from improper implementation
- Exposure of sensitive data due to user configuration errors

Always follow your organization's security policies and applicable laws.
