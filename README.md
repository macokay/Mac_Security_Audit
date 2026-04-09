<p align="center">
  <!-- ⚠️ MISSING: Project logo (recommended 120x120px PNG with transparent background) -->
  <!-- Example: <img src="images/logo.png" alt="Mac Security Audit" width="120" /> -->
</p>

<h1 align="center">Mac Security Audit</h1>

<p align="center">
  macOS endpoint security audit tool generating HTML compliance reports with risk ratings.
</p>

<p align="center">
  <a href="https://github.com/macokay/Mac_Security_Audit/releases">
    <img src="https://img.shields.io/github/v/release/macokay/Mac_Security_Audit" alt="GitHub release" />
  </a>
  <img src="https://img.shields.io/badge/Bash-4EAA25?logo=gnubash&logoColor=white" alt="Bash" />
  <a href="https://github.com/macokay/Mac_Security_Audit/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/License-Non--Commercial-blue.svg" alt="License" />
  </a>
</p>

<p align="center">
  <!-- ⚠️ MISSING: Banner image (recommended 1280x640px) -->
  <!-- Example: <img src="images/banner.png" alt="Mac Security Audit banner" width="100%" /> -->
</p>

<p align="center">
  <a href="https://www.buymeacoffee.com/macokay">
    <img src="https://img.shields.io/badge/Buy%20Me%20A%20Coffee-%23FFDD00.svg?logo=buy-me-a-coffee&logoColor=black" alt="Buy Me A Coffee" />
  </a>
</p>

---

## Features

- **50+ security checks** across encryption, firewall, SIP, Gatekeeper, updates, users, network, and more
- **HTML report** with risk scores, Cyber Essentials mapping, and interactive tables
- **JSON export** for automation and SIEM integration
- **Privacy mode** redacts hostnames, usernames, IPs, and serial numbers
- **No dependencies** — uses only native macOS CLI tools
- **Apple Silicon + Intel** support

---

## Requirements

| Requirement | Details |
|---|---|
| macOS | 12 Monterey or later |
| Bash | 3.2+ (ships with macOS) |
| Privileges | `sudo` recommended for complete results |

---

## Installation

Download the latest `audit.sh` from [GitHub Releases](https://github.com/macokay/Mac_Security_Audit/releases), or clone the repo:

```bash
git clone https://github.com/macokay/Mac_Security_Audit.git
cd Mac_Security_Audit
```

```bash
# Basic audit
bash audit.sh

# Full audit with sudo (recommended)
sudo bash audit.sh

# Custom output directory + JSON export
sudo bash audit.sh --output ~/Desktop --export-json

# Privacy mode (redacts hostname, username, IP, serial)
sudo bash audit.sh --privacy
```

---

## Data

### Sources

| Source | Usage |
|---|---|
| `system_profiler` | Hardware, OS, network, storage info |
| `fdesetup` | FileVault encryption status |
| `csrutil` | System Integrity Protection status |
| `spctl` | Gatekeeper status |
| `profiles` | MDM enrollment and configuration profiles |
| `softwareupdate` | Pending updates and update history |
| `dscl` | User accounts and group memberships |
| `socketfilterfw` | Application firewall status |
| `diskutil` | Disk and volume info, APFS encryption |
| `pmset` | Power management and sleep settings |

### Output

Generates a self-contained HTML report with risk scores and compliance mappings. Optional JSON export via `--export-json`.

---

## Known Limitations

- Some checks require `sudo` (e.g. FileVault key escrow, TCC database)
- Apple Silicon and Intel Macs have different security features (Secure Boot vs firmware password)
- macOS versions below 12 Monterey are not supported

---

## Credits

- [mr-r3b00t/windows_audit](https://github.com/mr-r3b00t/windows_audit) — original report style and risk scoring

---

## License

&copy; 2026 Mac O Kay. Free to use and modify for personal, non-commercial use. Attribution appreciated if you share or build upon this work. Commercial use is not permitted.
