# Mac Security Audit

macOS endpoint security audit tool generating HTML compliance reports with risk ratings.

Companion to the [Windows Security Audit Tool](https://github.com/macokay/win-security-audit) — same report style, same risk scoring, adapted for macOS.

## Features

- **50+ security checks** across encryption, firewall, SIP, Gatekeeper, updates, users, network, and more
- **HTML report** with risk scores, Cyber Essentials mapping, and interactive tables
- **JSON export** for automation and SIEM integration
- **Privacy mode** redacts hostnames, usernames, IPs, and serial numbers
- **No dependencies** — uses only native macOS CLI tools
- **Apple Silicon + Intel** support

## Getting started

```bash
# Basic audit
bash audit.sh

# Full audit with sudo (recommended)
sudo bash audit.sh

# Custom output + JSON export
sudo bash audit.sh --output ~/Desktop --export-json

# Privacy mode
sudo bash audit.sh --privacy
```

## Requirements

- macOS 12 Monterey or later
- Bash 3.2+ (ships with macOS)
- `sudo` recommended for complete results

## License

MIT
