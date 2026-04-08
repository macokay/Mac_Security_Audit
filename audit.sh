#!/usr/bin/env bash
# ============================================================================
# Mac Security Audit Tool v1.0.0
# Copyright (C) Mac O Kay. All rights reserved.
#
# macOS endpoint security audit tool generating HTML compliance reports.
# READ-ONLY — does not modify any system settings.
#
# Usage:
#   bash audit.sh [options]
#   sudo bash audit.sh [options]    (recommended for full results)
#
# Options:
#   --output <path>     Report output directory (default: current dir)
#   --skip-network      Skip network-related checks
#   --quiet             Suppress console output
#   --privacy           Redact hostnames, usernames, IPs, serials
#   --export-json       Also export JSON report
#   --report-name <n>   Custom prefix for report filename
#   --help              Show this help
# ============================================================================

set -euo pipefail

# ============================================================================
# CONFIGURATION & GLOBALS
# ============================================================================

AUDIT_VERSION="1.0.0"
AUDIT_DATE=$(date '+%Y-%m-%d %H:%M:%S')
HOSTNAME_RAW=$(scutil --get ComputerName 2>/dev/null || hostname -s)
OUTPUT_PATH="."
SKIP_NETWORK=false
QUIET=false
PRIVACY_MODE=false
EXPORT_JSON=false
REPORT_NAME=""
IS_ROOT=false

# Findings array — each entry is: "CATEGORY|NAME|RISK|DESCRIPTION|DETAILS|RECOMMENDATION|REFERENCE"
declare -a FINDINGS=()

# Risk level values for scoring
declare -A RISK_VALUES=(
    [Critical]=4 [High]=3 [Medium]=2 [Low]=1 [Info]=0
)

# ============================================================================
# ARGUMENT PARSING
# ============================================================================

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output)
            OUTPUT_PATH="$2"
            shift 2
            ;;
        --skip-network)
            SKIP_NETWORK=true
            shift
            ;;
        --quiet)
            QUIET=true
            shift
            ;;
        --privacy)
            PRIVACY_MODE=true
            shift
            ;;
        --export-json)
            EXPORT_JSON=true
            shift
            ;;
        --report-name)
            REPORT_NAME="$2"
            shift 2
            ;;
        --help)
            head -25 "$0" | tail -15
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

[[ $(id -u) -eq 0 ]] && IS_ROOT=true

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

log() {
    local level="$1" msg="$2"
    $QUIET && return
    local color
    case "$level" in
        INFO)    color="\033[0;36m" ;;
        WARN)    color="\033[0;33m" ;;
        ERROR)   color="\033[0;31m" ;;
        SUCCESS) color="\033[0;32m" ;;
        *)       color="\033[0m" ;;
    esac
    printf "${color}[%s] [%s] %s\033[0m\n" "$(date '+%H:%M:%S')" "$level" "$msg"
}

add_finding() {
    local category="$1" name="$2" risk="$3" description="$4"
    local details="${5:-}" recommendation="${6:-}" reference="${7:-}"

    FINDINGS+=("${category}|${name}|${risk}|${description}|${details}|${recommendation}|${reference}")

    if ! $QUIET; then
        local color
        case "$risk" in
            Critical) color="\033[0;31m" ;;
            High)     color="\033[0;33m" ;;
            Medium)   color="\033[0;33m" ;;
            Low)      color="\033[0;36m" ;;
            Info)     color="\033[0;37m" ;;
            *)        color="\033[0m" ;;
        esac
        printf "  [${color}%s\033[0m] %s\n" "${risk^^}" "$name"
    fi
}

# Read a macOS defaults value safely
read_default() {
    local domain="$1" key="$2" default_val="${3:-}"
    local val
    val=$(defaults read "$domain" "$key" 2>/dev/null) || val="$default_val"
    echo "$val"
}

# HTML-encode a string
html_encode() {
    local s="$1"
    s="${s//&/&amp;}"
    s="${s//</&lt;}"
    s="${s//>/&gt;}"
    s="${s//\"/&quot;}"
    s="${s//\'/&#39;}"
    echo "$s"
}

# ============================================================================
# AUDIT MODULES
# ============================================================================

get_system_information() {
    log INFO "Gathering System Information..."

    # OS info
    OS_VERSION=$(sw_vers -productVersion 2>/dev/null || echo "Unknown")
    OS_BUILD=$(sw_vers -buildVersion 2>/dev/null || echo "Unknown")
    OS_NAME=$(sw_vers -productName 2>/dev/null || echo "macOS")

    # Hardware
    CHIP=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "Unknown")
    MODEL=$(sysctl -n hw.model 2>/dev/null || echo "Unknown")
    SERIAL=$(system_profiler SPHardwareDataType 2>/dev/null | awk -F': ' '/Serial Number/{print $2}' || echo "Unknown")
    TOTAL_RAM_BYTES=$(sysctl -n hw.memsize 2>/dev/null || echo "0")
    TOTAL_RAM_GB=$(( TOTAL_RAM_BYTES / 1073741824 ))
    CPU_CORES=$(sysctl -n hw.physicalcpu 2>/dev/null || echo "?")
    CPU_THREADS=$(sysctl -n hw.logicalcpu 2>/dev/null || echo "?")

    # Model friendly name
    MODEL_NAME=$(system_profiler SPHardwareDataType 2>/dev/null | awk -F': ' '/Model Name/{print $2}' || echo "$MODEL")

    # Apple Silicon detection
    IS_APPLE_SILICON=false
    if [[ "$CHIP" == *"Apple"* ]] || sysctl -n hw.optional.arm64 &>/dev/null; then
        IS_APPLE_SILICON=true
    fi

    # Uptime
    BOOT_TIME=$(sysctl -n kern.boottime 2>/dev/null | awk -F'[= ,}]' '{print $4}')
    if [[ -n "$BOOT_TIME" ]]; then
        UPTIME_SECS=$(( $(date +%s) - BOOT_TIME ))
        UPTIME_DAYS=$(( UPTIME_SECS / 86400 ))
        UPTIME_HOURS=$(( (UPTIME_SECS % 86400) / 3600 ))
        UPTIME_STR="${UPTIME_DAYS}d ${UPTIME_HOURS}h"
    else
        UPTIME_STR="Unknown"
    fi

    # Current user
    CURRENT_USER=$(whoami)

    add_finding "System Info" "System Overview" "Info" \
        "Basic system information collected" \
        "OS: ${OS_NAME} ${OS_VERSION} (${OS_BUILD}) | Chip: ${CHIP} | Model: ${MODEL_NAME}"

    add_finding "System Info" "Hardware Summary" "Info" \
        "Hardware identification" \
        "Model: ${MODEL_NAME} (${MODEL})\nSerial: ${SERIAL}\nChip: ${CHIP} (${CPU_CORES}C/${CPU_THREADS}T)\nRAM: ${TOTAL_RAM_GB} GB\nUptime: ${UPTIME_STR}"

    # Check macOS version support
    local major_ver
    major_ver=$(echo "$OS_VERSION" | cut -d. -f1)
    if [[ "$major_ver" -lt 12 ]]; then
        add_finding "System Info" "Unsupported macOS Version" "High" \
            "macOS ${OS_VERSION} may be out of support" \
            "Current: ${OS_VERSION}. macOS 12 Monterey is minimum recommended." \
            "Update to a supported macOS version" \
            "Apple Security Updates"
    elif [[ "$major_ver" -lt 14 ]]; then
        add_finding "System Info" "Older macOS Version" "Medium" \
            "macOS ${OS_VERSION} — check Apple support status" \
            "Current: ${OS_VERSION}" \
            "Consider updating to latest macOS" \
            "Apple Security Updates"
    else
        add_finding "System Info" "macOS Version Supported" "Info" \
            "macOS version appears current" \
            "Current: ${OS_NAME} ${OS_VERSION} (${OS_BUILD})"
    fi

    # Admin check
    if ! $IS_ROOT; then
        add_finding "System Info" "Scan Run Without sudo" "Medium" \
            "Audit not run as root — some checks will return limited results" \
            "Affected: FileVault key escrow, TCC database, some security settings" \
            "Re-run with: sudo bash audit.sh"
    fi
}

test_filevault() {
    log INFO "Checking FileVault Encryption..."

    local fv_status
    fv_status=$(fdesetup status 2>/dev/null || echo "Unknown")

    if echo "$fv_status" | grep -q "FileVault is On"; then
        add_finding "Encryption" "FileVault Enabled" "Info" \
            "FileVault full-disk encryption is enabled" \
            "$fv_status"

        # Check if institutional recovery key exists
        if $IS_ROOT; then
            if fdesetup hasinstitutionalrecoverykey 2>/dev/null | grep -q "true"; then
                add_finding "Encryption" "Institutional Recovery Key" "Info" \
                    "Institutional recovery key is present" \
                    "Key escrowed to MDM or institutional keychain"
            fi
            if fdesetup haspersonalrecoverykey 2>/dev/null | grep -q "true"; then
                add_finding "Encryption" "Personal Recovery Key" "Info" \
                    "Personal recovery key exists"
            fi
        fi
    elif echo "$fv_status" | grep -q "FileVault is Off"; then
        add_finding "Encryption" "FileVault Not Enabled" "Critical" \
            "FileVault full-disk encryption is not enabled — data at rest is unprotected" \
            "$fv_status" \
            "Enable FileVault: System Settings > Privacy & Security > FileVault" \
            "CIS Apple macOS Benchmark"
    else
        add_finding "Encryption" "FileVault Status Unknown" "Medium" \
            "Could not determine FileVault status" \
            "$fv_status" \
            "Run with sudo for accurate results"
    fi
}

test_sip() {
    log INFO "Checking System Integrity Protection..."

    local sip_status
    sip_status=$(csrutil status 2>/dev/null || echo "Unknown")

    if echo "$sip_status" | grep -q "enabled"; then
        add_finding "System Protection" "SIP Enabled" "Info" \
            "System Integrity Protection is enabled" \
            "$sip_status"
    elif echo "$sip_status" | grep -q "disabled"; then
        add_finding "System Protection" "SIP Disabled" "Critical" \
            "System Integrity Protection is disabled — system files are unprotected" \
            "$sip_status" \
            "Enable SIP: Boot to Recovery Mode, run csrutil enable" \
            "Apple Platform Security"
    else
        add_finding "System Protection" "SIP Status Unknown" "Medium" \
            "Could not determine SIP status" \
            "$sip_status"
    fi
}

test_gatekeeper() {
    log INFO "Checking Gatekeeper..."

    local gk_status
    gk_status=$(spctl --status 2>/dev/null || echo "Unknown")

    if echo "$gk_status" | grep -q "assessments enabled"; then
        add_finding "System Protection" "Gatekeeper Enabled" "Info" \
            "Gatekeeper is enabled — unsigned apps will be blocked" \
            "$gk_status"
    elif echo "$gk_status" | grep -q "assessments disabled"; then
        add_finding "System Protection" "Gatekeeper Disabled" "High" \
            "Gatekeeper is disabled — any app can run without verification" \
            "$gk_status" \
            "Enable: sudo spctl --master-enable" \
            "CIS Apple macOS Benchmark"
    else
        add_finding "System Protection" "Gatekeeper Status Unknown" "Medium" \
            "Could not determine Gatekeeper status" \
            "$gk_status"
    fi
}

test_firewall() {
    log INFO "Checking Application Firewall..."

    local fw_bin="/usr/libexec/ApplicationFirewall/socketfilterfw"

    if [[ ! -x "$fw_bin" ]]; then
        add_finding "Firewall" "Firewall Binary Not Found" "Medium" \
            "Could not locate Application Firewall binary"
        return
    fi

    local fw_global fw_stealth fw_block_all
    fw_global=$("$fw_bin" --getglobalstate 2>/dev/null || echo "")
    fw_stealth=$("$fw_bin" --getstealthmode 2>/dev/null || echo "")
    fw_block_all=$("$fw_bin" --getblockall 2>/dev/null || echo "")

    if echo "$fw_global" | grep -qi "enabled"; then
        add_finding "Firewall" "Application Firewall Enabled" "Info" \
            "macOS Application Firewall is enabled" \
            "Global: Enabled"
    else
        add_finding "Firewall" "Application Firewall Disabled" "High" \
            "macOS Application Firewall is not enabled" \
            "Global: Disabled" \
            "Enable: System Settings > Network > Firewall > Turn On" \
            "CIS Apple macOS Benchmark"
    fi

    if echo "$fw_stealth" | grep -qi "enabled"; then
        add_finding "Firewall" "Stealth Mode Enabled" "Info" \
            "Stealth mode is enabled — system won't respond to probes" \
            "$fw_stealth"
    else
        add_finding "Firewall" "Stealth Mode Disabled" "Low" \
            "Stealth mode is not enabled" \
            "$fw_stealth" \
            "Enable stealth mode for reduced network visibility"
    fi
}

test_user_accounts() {
    log INFO "Checking User Accounts..."

    # List non-system users (UID >= 500)
    local users
    users=$(dscl . -list /Users UniqueID 2>/dev/null | awk '$2 >= 500 {print $1}')
    local user_count
    user_count=$(echo "$users" | grep -c . || echo "0")

    # Admin users
    local admins
    admins=$(dscl . -read /Groups/admin GroupMembership 2>/dev/null | sed 's/GroupMembership: //' || echo "")
    local admin_count
    admin_count=$(echo "$admins" | wc -w | tr -d ' ')

    if [[ "$admin_count" -gt 2 ]]; then
        add_finding "User Accounts" "Multiple Admin Accounts" "Medium" \
            "More than 2 accounts have admin privileges" \
            "Admin count: ${admin_count}\nAdmins: ${admins}" \
            "Minimize admin accounts — use standard accounts for daily work" \
            "Principle of Least Privilege"
    else
        add_finding "User Accounts" "Admin Accounts" "Info" \
            "Admin accounts enumerated" \
            "Admin count: ${admin_count}\nAdmins: ${admins}"
    fi

    # Guest account
    local guest_enabled
    guest_enabled=$(read_default "/Library/Preferences/com.apple.loginwindow" GuestEnabled "0")
    if [[ "$guest_enabled" == "1" ]]; then
        add_finding "User Accounts" "Guest Account Enabled" "Medium" \
            "Guest account is enabled" \
            "GuestEnabled: 1" \
            "Disable guest account unless required" \
            "CIS Apple macOS Benchmark"
    else
        add_finding "User Accounts" "Guest Account Disabled" "Info" \
            "Guest account is properly disabled"
    fi

    # Auto-login
    local auto_login
    auto_login=$(read_default "/Library/Preferences/com.apple.loginwindow" autoLoginUser "")
    if [[ -n "$auto_login" ]]; then
        add_finding "User Accounts" "Auto-Login Enabled" "High" \
            "Automatic login is enabled — bypasses authentication" \
            "Auto-login user: ${auto_login}" \
            "Disable: System Settings > Users & Groups > Automatic login: Off" \
            "CIS Apple macOS Benchmark"
    else
        add_finding "User Accounts" "Auto-Login Disabled" "Info" \
            "Automatic login is properly disabled"
    fi

    add_finding "User Accounts" "User Summary" "Info" \
        "Local user accounts enumerated" \
        "Total users (UID>=500): ${user_count}\nUsers: $(echo $users | tr '\n' ', ')"
}

test_password_policy() {
    log INFO "Checking Password Policy..."

    local pw_policy
    pw_policy=$(pwpolicy getaccountpolicies 2>/dev/null || echo "")

    if [[ -z "$pw_policy" ]] || echo "$pw_policy" | grep -q "No policies"; then
        add_finding "Password Policy" "No Custom Password Policy" "Medium" \
            "No custom password policy is configured" \
            "Using macOS defaults" \
            "Consider deploying password policy via MDM configuration profile"
    else
        add_finding "Password Policy" "Password Policy Configured" "Info" \
            "Custom password policy is in place"
    fi

    # Screen lock password requirement
    local ask_for_pw
    ask_for_pw=$(read_default "com.apple.screensaver" askForPassword "0")
    local ask_delay
    ask_delay=$(read_default "com.apple.screensaver" askForPasswordDelay "0")

    if [[ "$ask_for_pw" != "1" ]]; then
        add_finding "Password Policy" "No Password on Wake" "High" \
            "Password is not required after sleep or screen saver" \
            "askForPassword: ${ask_for_pw}" \
            "Enable: System Settings > Lock Screen > Require password after screen saver" \
            "CIS Apple macOS Benchmark"
    elif [[ "$ask_delay" -gt 5 ]]; then
        add_finding "Password Policy" "Long Password Delay" "Medium" \
            "Password delay after sleep is more than 5 seconds" \
            "askForPasswordDelay: ${ask_delay} seconds" \
            "Set to Immediately or max 5 seconds"
    else
        add_finding "Password Policy" "Password on Wake" "Info" \
            "Password required after sleep/screen saver" \
            "Delay: ${ask_delay} seconds"
    fi
}

test_screen_lock() {
    log INFO "Checking Screen Lock Settings..."

    # Screen saver idle time
    local idle_time
    idle_time=$(read_default "com.apple.screensaver" idleTime "0")

    if [[ "$idle_time" -eq 0 ]] || [[ "$idle_time" -gt 1200 ]]; then
        add_finding "Session Security" "No/Long Screen Lock Timeout" "Medium" \
            "Screen saver idle time is not set or exceeds 20 minutes" \
            "idleTime: ${idle_time} seconds" \
            "Set to 900 seconds (15 minutes) or less" \
            "CIS Apple macOS Benchmark"
    else
        add_finding "Session Security" "Screen Lock Timeout" "Info" \
            "Screen saver activates after $(( idle_time / 60 )) minutes" \
            "idleTime: ${idle_time} seconds"
    fi

    # Login window settings
    local show_name_password
    show_name_password=$(read_default "/Library/Preferences/com.apple.loginwindow" SHOWFULLNAME "0")
    if [[ "$show_name_password" != "1" ]]; then
        add_finding "Session Security" "Login Window Shows User List" "Low" \
            "Login window displays user list instead of name+password fields" \
            "SHOWFULLNAME: ${show_name_password}" \
            "Set to name+password for better security"
    fi

    # Lock message
    local lock_msg
    lock_msg=$(read_default "/Library/Preferences/com.apple.loginwindow" LoginwindowText "")
    if [[ -z "$lock_msg" ]]; then
        add_finding "Session Security" "No Login Banner" "Low" \
            "No login window message/banner configured" \
            "" \
            "Configure a login banner for compliance"
    else
        add_finding "Session Security" "Login Banner Configured" "Info" \
            "Login window message is set" \
            "Message: ${lock_msg}"
    fi
}

test_sharing_services() {
    log INFO "Checking Sharing Services..."

    # SSH / Remote Login
    local ssh_status
    ssh_status=$(systemsetup -getremotelogin 2>/dev/null || echo "Unknown")
    if echo "$ssh_status" | grep -qi "on"; then
        add_finding "Sharing" "Remote Login (SSH) Enabled" "Medium" \
            "SSH remote login is enabled" \
            "$ssh_status" \
            "Disable if not required: System Settings > General > Sharing > Remote Login"
    else
        add_finding "Sharing" "Remote Login (SSH) Disabled" "Info" \
            "SSH remote login is properly disabled"
    fi

    # Screen Sharing
    local vnc_running
    vnc_running=$(launchctl list 2>/dev/null | grep -c "com.apple.screensharing" || echo "0")
    if [[ "$vnc_running" -gt 0 ]]; then
        add_finding "Sharing" "Screen Sharing Enabled" "Medium" \
            "Screen Sharing (VNC) is running" \
            "" \
            "Disable if not required"
    fi

    # Remote Management (ARD)
    local ard_running
    ard_running=$(launchctl list 2>/dev/null | grep -c "com.apple.RemoteDesktop" || echo "0")
    if [[ "$ard_running" -gt 0 ]]; then
        add_finding "Sharing" "Remote Management (ARD) Enabled" "Medium" \
            "Apple Remote Desktop agent is running" \
            "" \
            "Disable if not required"
    fi

    # File Sharing (SMB)
    local smb_running
    smb_running=$(launchctl list 2>/dev/null | grep -c "com.apple.smbd" || echo "0")
    if [[ "$smb_running" -gt 0 ]]; then
        add_finding "Sharing" "File Sharing (SMB) Enabled" "Low" \
            "SMB file sharing is running" \
            "" \
            "Disable if not required"
    fi

    # AirDrop
    local airdrop_status
    airdrop_status=$(read_default "com.apple.NetworkBrowser" DisableAirDrop "0")
    if [[ "$airdrop_status" != "1" ]]; then
        add_finding "Sharing" "AirDrop Enabled" "Info" \
            "AirDrop is not disabled" \
            "Consider restricting AirDrop to Contacts Only or disabling"
    fi

    # Bluetooth sharing
    local bt_sharing
    bt_sharing=$(read_default "/Library/Preferences/com.apple.Bluetooth" PrefKeyServicesEnabled "0")
    if [[ "$bt_sharing" == "1" ]]; then
        add_finding "Sharing" "Bluetooth Sharing Enabled" "Low" \
            "Bluetooth sharing is enabled" \
            "" \
            "Disable if not required"
    fi
}

test_mdm_enrollment() {
    log INFO "Checking MDM Enrollment..."

    local profiles_output
    profiles_output=$(profiles status -type enrollment 2>/dev/null || echo "")

    if echo "$profiles_output" | grep -qi "MDM enrollment: Yes"; then
        add_finding "MDM" "Device is MDM Enrolled" "Info" \
            "This device is enrolled in Mobile Device Management" \
            "$profiles_output"
    elif echo "$profiles_output" | grep -qi "MDM enrollment: No"; then
        add_finding "MDM" "Device Not MDM Enrolled" "Medium" \
            "This device does not appear to be enrolled in MDM" \
            "$profiles_output" \
            "Consider enrolling in MDM for centralized management"
    else
        add_finding "MDM" "MDM Status Unknown" "Info" \
            "Could not determine MDM enrollment status" \
            "$profiles_output"
    fi

    # Count installed configuration profiles
    local profile_count
    profile_count=$(profiles list 2>/dev/null | grep -c "attribute:" || echo "0")
    if [[ "$profile_count" -gt 0 ]]; then
        add_finding "MDM" "Configuration Profiles Installed" "Info" \
            "${profile_count} configuration profile(s) installed"
    fi
}

test_updates() {
    log INFO "Checking Software Update Configuration..."

    # Auto update settings
    local auto_check auto_download auto_install auto_system
    auto_check=$(read_default "/Library/Preferences/com.apple.SoftwareUpdate" AutomaticCheckEnabled "0")
    auto_download=$(read_default "/Library/Preferences/com.apple.SoftwareUpdate" AutomaticDownload "0")
    auto_install=$(read_default "/Library/Preferences/com.apple.SoftwareUpdate" AutomaticallyInstallMacOSUpdates "0")
    auto_system=$(read_default "/Library/Preferences/com.apple.SoftwareUpdate" CriticalUpdateInstall "0")

    if [[ "$auto_check" != "1" ]]; then
        add_finding "Updates" "Automatic Update Check Disabled" "High" \
            "Automatic checking for updates is disabled" \
            "AutomaticCheckEnabled: ${auto_check}" \
            "Enable: System Settings > General > Software Update > Automatic Updates"
    fi

    if [[ "$auto_system" != "1" ]]; then
        add_finding "Updates" "Critical Updates Not Auto-Installed" "Medium" \
            "Critical/security updates are not set to install automatically" \
            "CriticalUpdateInstall: ${auto_system}" \
            "Enable automatic security update installation"
    fi

    if [[ "$auto_check" == "1" && "$auto_system" == "1" ]]; then
        add_finding "Updates" "Automatic Updates Configured" "Info" \
            "Automatic update checks and critical updates are enabled" \
            "Check: ${auto_check}, Download: ${auto_download}, Install macOS: ${auto_install}, Critical: ${auto_system}"
    fi

    # Rapid Security Responses
    local rsr_enabled
    rsr_enabled=$(read_default "/Library/Preferences/com.apple.SoftwareUpdate" AllowPreReleaseInstallation "")
    # This is best checked via profiles in practice

    # Check last update
    local last_update
    last_update=$(softwareupdate --history 2>/dev/null | tail -5 || echo "Could not retrieve")
    add_finding "Updates" "Recent Update History" "Info" \
        "Last updates installed" \
        "$last_update"
}

test_xprotect() {
    log INFO "Checking XProtect and MRT..."

    # XProtect version
    local xp_version xp_plist
    xp_plist="/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/version.plist"
    if [[ -f "$xp_plist" ]]; then
        xp_version=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$xp_plist" 2>/dev/null || echo "Unknown")
        add_finding "Malware Protection" "XProtect Active" "Info" \
            "XProtect malware definitions are present" \
            "Version: ${xp_version}"
    else
        # Try alternate path for newer macOS
        xp_plist="/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/version.plist"
        if [[ -f "$xp_plist" ]]; then
            xp_version=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$xp_plist" 2>/dev/null || echo "Unknown")
            add_finding "Malware Protection" "XProtect Active" "Info" \
                "XProtect malware definitions are present" \
                "Version: ${xp_version}"
        else
            add_finding "Malware Protection" "XProtect Not Found" "High" \
                "XProtect definitions not found in expected location" \
                "" \
                "Verify macOS installation integrity"
        fi
    fi

    # XProtect Remediator (replaces MRT)
    if [[ -d "/Library/Apple/System/Library/CoreServices/XProtect.app" ]]; then
        add_finding "Malware Protection" "XProtect Remediator Present" "Info" \
            "XProtect Remediator (background malware scanning) is present"
    fi

    # Check if third-party AV is installed
    local av_apps
    av_apps=$(ls /Applications/ 2>/dev/null | grep -iE '(norton|symantec|mcafee|kaspersky|bitdefender|avast|avg|malwarebytes|sophos|crowdstrike|sentinel|carbon black|cylance)' || echo "")
    if [[ -n "$av_apps" ]]; then
        add_finding "Malware Protection" "Third-Party AV Detected" "Info" \
            "Third-party antivirus/security software detected" \
            "Apps: ${av_apps}"
    fi
}

test_secure_boot() {
    log INFO "Checking Secure Boot..."

    if $IS_APPLE_SILICON; then
        # Apple Silicon — check startup security
        # This requires booting into recovery, but we can check the policy
        local bputil_output
        bputil_output=$(bputil -d 2>/dev/null || echo "")

        if [[ -n "$bputil_output" ]]; then
            if echo "$bputil_output" | grep -q "Full Security"; then
                add_finding "Hardware Security" "Full Security Boot" "Info" \
                    "Apple Silicon startup security is set to Full Security" \
                    "Only signed and trusted software can run at boot"
            elif echo "$bputil_output" | grep -q "Reduced Security"; then
                add_finding "Hardware Security" "Reduced Security Boot" "Medium" \
                    "Startup security is set to Reduced Security" \
                    "" \
                    "Set to Full Security unless kernel extensions are required"
            fi
        else
            add_finding "Hardware Security" "Apple Silicon Mac" "Info" \
                "Apple Silicon detected — Secure Enclave provides hardware security" \
                "Chip: ${CHIP}"
        fi
    else
        # Intel Mac — check for T2 chip and firmware password
        local t2_present
        t2_present=$(system_profiler SPiBridgeDataType 2>/dev/null | grep -c "T2" || echo "0")

        if [[ "$t2_present" -gt 0 ]]; then
            add_finding "Hardware Security" "T2 Security Chip" "Info" \
                "T2 security chip detected — provides Secure Boot and hardware encryption"
        else
            add_finding "Hardware Security" "No T2 Chip" "Low" \
                "No T2 security chip detected — older Intel Mac" \
                "Hardware-level security features are limited"
        fi

        # Firmware password (requires root)
        if $IS_ROOT; then
            local fw_pass
            fw_pass=$(firmwarepasswd -check 2>/dev/null || echo "Unknown")
            if echo "$fw_pass" | grep -q "Yes"; then
                add_finding "Hardware Security" "Firmware Password Set" "Info" \
                    "EFI firmware password is configured"
            elif echo "$fw_pass" | grep -q "No"; then
                add_finding "Hardware Security" "No Firmware Password" "Medium" \
                    "No firmware password set — boot from external media is unrestricted" \
                    "" \
                    "Set firmware password to prevent unauthorized boot device changes"
            fi
        fi
    fi
}

test_network_config() {
    log INFO "Checking Network Configuration..."

    $SKIP_NETWORK && {
        add_finding "Network" "Network Checks Skipped" "Info" "Network checks skipped per user request"
        return
    }

    # Wi-Fi security
    local wifi_interface wifi_security
    wifi_interface=$(networksetup -listallhardwareports 2>/dev/null | awk '/Wi-Fi|AirPort/{getline; print $2}' || echo "")
    if [[ -n "$wifi_interface" ]]; then
        # Check current Wi-Fi connection security
        wifi_security=$(system_profiler SPAirPortDataType 2>/dev/null | awk '/Security:/{print $2; exit}' || echo "Unknown")
        if [[ "$wifi_security" == "WPA2" ]] || [[ "$wifi_security" == "WPA3" ]]; then
            add_finding "Network" "Wi-Fi Security" "Info" \
                "Current Wi-Fi using ${wifi_security}" \
                "Security: ${wifi_security}"
        elif [[ "$wifi_security" == "WEP" ]] || [[ "$wifi_security" == "None" ]]; then
            add_finding "Network" "Weak Wi-Fi Security" "High" \
                "Current Wi-Fi using weak or no encryption: ${wifi_security}" \
                "" \
                "Connect to WPA2/WPA3 secured network"
        fi
    fi

    # DNS settings
    local dns_servers
    dns_servers=$(scutil --dns 2>/dev/null | awk '/nameserver\[0\]/{print $3}' | sort -u | head -5 || echo "")
    if [[ -n "$dns_servers" ]]; then
        add_finding "Network" "DNS Configuration" "Info" \
            "DNS servers configured" \
            "Servers: $(echo $dns_servers | tr '\n' ', ')"
    fi

    # Check for VPN configurations
    local vpn_configs
    vpn_configs=$(scutil --nc list 2>/dev/null | grep -c "VPN" || echo "0")
    if [[ "$vpn_configs" -gt 0 ]]; then
        add_finding "Network" "VPN Configurations" "Info" \
            "${vpn_configs} VPN configuration(s) found"
    fi
}

test_disk_security() {
    log INFO "Checking Disk and Storage..."

    # APFS volumes
    local apfs_info
    apfs_info=$(diskutil apfs list 2>/dev/null || echo "")

    if [[ -n "$apfs_info" ]]; then
        add_finding "Storage" "APFS File System" "Info" \
            "APFS file system detected"
    fi

    # Disk usage
    local disk_usage
    disk_usage=$(df -h / 2>/dev/null | tail -1 || echo "")
    local pct_used
    pct_used=$(echo "$disk_usage" | awk '{print $5}' | tr -d '%')

    if [[ -n "$pct_used" ]]; then
        if [[ "$pct_used" -gt 95 ]]; then
            add_finding "Storage" "Critical Low Disk Space" "High" \
                "Root volume is ${pct_used}% full" \
                "$disk_usage" \
                "Free up disk space immediately"
        elif [[ "$pct_used" -gt 90 ]]; then
            add_finding "Storage" "Low Disk Space" "Medium" \
                "Root volume is ${pct_used}% full" \
                "$disk_usage" \
                "Consider freeing disk space"
        else
            add_finding "Storage" "Disk Space" "Info" \
                "Root volume is ${pct_used}% used" \
                "$disk_usage"
        fi
    fi
}

test_privacy_settings() {
    log INFO "Checking Privacy Settings..."

    # Location Services
    local location_enabled
    if $IS_ROOT; then
        location_enabled=$(defaults read /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd LocationServicesEnabled 2>/dev/null || echo "Unknown")
    else
        location_enabled="Unknown (requires sudo)"
    fi

    if [[ "$location_enabled" == "0" ]]; then
        add_finding "Privacy" "Location Services Disabled" "Info" \
            "Location Services are disabled"
    elif [[ "$location_enabled" == "1" ]]; then
        add_finding "Privacy" "Location Services Enabled" "Info" \
            "Location Services are enabled" \
            "Review which apps have location access in System Settings"
    fi

    # Analytics sharing
    local analytics_sharing
    analytics_sharing=$(read_default "/Library/Application Support/CrashReporter/DiagnosticMessagesHistory" AutoSubmit "0")
    if [[ "$analytics_sharing" == "1" ]]; then
        add_finding "Privacy" "Analytics Sharing Enabled" "Info" \
            "Mac analytics are being shared with Apple" \
            "Consider disabling for privacy"
    fi

    # Siri
    local siri_enabled
    siri_enabled=$(read_default "com.apple.assistant.support" "Assistant Enabled" "0")
    if [[ "$siri_enabled" == "1" ]]; then
        add_finding "Privacy" "Siri Enabled" "Info" \
            "Siri is enabled" \
            "Review Siri & Spotlight privacy settings"
    fi
}

test_find_my_mac() {
    log INFO "Checking Find My Mac..."

    local fmm_enabled
    fmm_enabled=$(nvram -x -p 2>/dev/null | grep -c "fmm-mobileme-token-FMM" || echo "0")

    if [[ "$fmm_enabled" -gt 0 ]]; then
        add_finding "Device Security" "Find My Mac Enabled" "Info" \
            "Find My Mac appears to be configured"
    else
        add_finding "Device Security" "Find My Mac Not Detected" "Low" \
            "Find My Mac does not appear to be enabled" \
            "" \
            "Enable Find My Mac for remote lock/wipe capability"
    fi
}

test_time_machine() {
    log INFO "Checking Time Machine..."

    local tm_status
    tm_status=$(tmutil status 2>/dev/null || echo "")

    local tm_destinations
    tm_destinations=$(tmutil destinationinfo 2>/dev/null || echo "")

    if echo "$tm_destinations" | grep -q "No destinations"; then
        add_finding "Backup" "No Time Machine Backup" "Medium" \
            "Time Machine is not configured with any backup destination" \
            "" \
            "Configure Time Machine for regular backups"
    elif [[ -n "$tm_destinations" ]]; then
        add_finding "Backup" "Time Machine Configured" "Info" \
            "Time Machine backup destination is configured" \
            "$tm_destinations"
    fi
}

test_software_inventory() {
    log INFO "Building Software Inventory..."

    APP_COUNT=$(ls -1 /Applications/ 2>/dev/null | wc -l | tr -d ' ')
    add_finding "Software" "Applications Installed" "Info" \
        "${APP_COUNT} applications in /Applications" \
        "$(ls -1 /Applications/ 2>/dev/null | head -30 || echo '(could not list)')"

    # Homebrew
    if command -v brew &>/dev/null; then
        local brew_count
        brew_count=$(brew list --formula 2>/dev/null | wc -l | tr -d ' ')
        local brew_cask_count
        brew_cask_count=$(brew list --cask 2>/dev/null | wc -l | tr -d ' ')
        add_finding "Software" "Homebrew Installed" "Info" \
            "Homebrew package manager detected" \
            "Formulae: ${brew_count}, Casks: ${brew_cask_count}"
    fi
}

test_remote_access_tools() {
    log INFO "Checking Remote Access Tools..."

    local remote_tools=("TeamViewer" "AnyDesk" "LogMeIn" "Splashtop" "ConnectWise" "ScreenConnect" "RustDesk")

    for tool in "${remote_tools[@]}"; do
        if ls /Applications/ 2>/dev/null | grep -qi "$tool"; then
            add_finding "Software" "Remote Access: ${tool}" "Info" \
                "Remote access tool detected: ${tool}" \
                "" \
                "Verify this tool is authorized by security policy"
        fi
    done
}

test_browser_extensions() {
    log INFO "Checking Browser Extensions..."

    local ext_count=0

    # Chrome extensions
    local chrome_ext_dir="$HOME/Library/Application Support/Google/Chrome/Default/Extensions"
    if [[ -d "$chrome_ext_dir" ]]; then
        local chrome_count
        chrome_count=$(ls -1 "$chrome_ext_dir" 2>/dev/null | grep -v "Temp" | wc -l | tr -d ' ')
        ext_count=$((ext_count + chrome_count))
        add_finding "Browser" "Chrome Extensions" "Info" \
            "${chrome_count} Chrome extension(s) installed"
    fi

    # Safari extensions
    local safari_ext_dir="$HOME/Library/Safari/Extensions"
    if [[ -d "$safari_ext_dir" ]]; then
        local safari_count
        safari_count=$(ls -1 "$safari_ext_dir" 2>/dev/null | wc -l | tr -d ' ')
        if [[ "$safari_count" -gt 0 ]]; then
            ext_count=$((ext_count + safari_count))
            add_finding "Browser" "Safari Extensions" "Info" \
                "${safari_count} Safari extension(s) found"
        fi
    fi

    # Firefox extensions
    local ff_profiles="$HOME/Library/Application Support/Firefox/Profiles"
    if [[ -d "$ff_profiles" ]]; then
        local ff_count=0
        for profile_dir in "$ff_profiles"/*/; do
            if [[ -f "${profile_dir}extensions.json" ]]; then
                local profile_ext
                profile_ext=$(python3 -c "
import json, sys
try:
    d = json.load(open('${profile_dir}extensions.json'))
    print(len([a for a in d.get('addons',[]) if a.get('type')=='extension' and a.get('location') not in ('app-system-defaults','app-builtin')]))
except: print(0)
" 2>/dev/null || echo "0")
                ff_count=$((ff_count + profile_ext))
            fi
        done
        if [[ "$ff_count" -gt 0 ]]; then
            ext_count=$((ext_count + ff_count))
            add_finding "Browser" "Firefox Extensions" "Info" \
                "${ff_count} Firefox extension(s) found"
        fi
    fi

    if [[ "$ext_count" -gt 0 ]]; then
        add_finding "Browser" "Browser Extensions Total" "Info" \
            "${ext_count} browser extension(s) found across all browsers"
    fi
}

# ============================================================================
# HTML REPORT GENERATION
# ============================================================================

generate_html_report() {
    log INFO "Generating HTML Report..."

    local critical=0 high=0 medium=0 low=0 info=0
    for f in "${FINDINGS[@]}"; do
        local risk
        risk=$(echo "$f" | cut -d'|' -f3)
        case "$risk" in
            Critical) ((critical++)) ;;
            High)     ((high++)) ;;
            Medium)   ((medium++)) ;;
            Low)      ((low++)) ;;
            Info)     ((info++)) ;;
        esac
    done

    local total_weight=$(( critical * 25 + high * 15 + medium * 8 + low * 3 ))
    local score=$(( 100 - total_weight ))
    [[ $score -lt 0 ]] && score=0

    local score_color
    if [[ $score -ge 80 ]]; then score_color="#28a745"
    elif [[ $score -ge 60 ]]; then score_color="#ffc107"
    elif [[ $score -ge 40 ]]; then score_color="#fd7e14"
    else score_color="#dc3545"
    fi

    local score_grade
    if [[ $score -ge 90 ]]; then score_grade="A"
    elif [[ $score -ge 80 ]]; then score_grade="B"
    elif [[ $score -ge 70 ]]; then score_grade="C"
    elif [[ $score -ge 60 ]]; then score_grade="D"
    else score_grade="F"
    fi

    local admin_badge
    if $IS_ROOT; then
        admin_badge="<span style='color:#90EE90;'>[OK] root</span>"
    else
        admin_badge="<span style='color:#ff6b6b;font-weight:bold;'>[!!] NOT ROOT</span>"
    fi

    local report_hostname="$HOSTNAME_RAW"
    $PRIVACY_MODE && report_hostname="REDACTED"

    # Build findings HTML
    local findings_html=""
    local prev_cat=""

    # Sort findings by category then risk (highest first)
    local sorted_findings
    sorted_findings=$(for i in "${!FINDINGS[@]}"; do
        local f="${FINDINGS[$i]}"
        local cat risk
        cat=$(echo "$f" | cut -d'|' -f1)
        risk=$(echo "$f" | cut -d'|' -f3)
        local rv=${RISK_VALUES[$risk]:-0}
        printf "%s\t%s\t%s\n" "$cat" "$rv" "$i"
    done | sort -t$'\t' -k1,1 -k2,2rn)

    while IFS=$'\t' read -r cat rv idx; do
        local f="${FINDINGS[$idx]}"
        local name risk desc details rec ref
        IFS='|' read -r cat name risk desc details rec ref <<< "$f"

        if [[ "$cat" != "$prev_cat" ]]; then
            [[ -n "$prev_cat" ]] && findings_html+="</div></div>"
            local cat_id
            cat_id=$(echo "$cat" | tr ' ' '-' | tr -cd '[:alnum:]-')
            findings_html+="<div class='section' id='${cat_id}'>"
            findings_html+="<div class='section-header'><span>$(html_encode "$cat")</span></div>"
            findings_html+="<div class='section-content'>"
            prev_cat="$cat"
        fi

        local risk_class="risk-$(echo "$risk" | tr '[:upper:]' '[:lower:]')"
        local details_html=""
        [[ -n "$details" ]] && details_html="<div class='finding-details'>$(html_encode "$details")</div>"
        local rec_html=""
        [[ -n "$rec" ]] && rec_html="<div class='recommendation'>$(html_encode "$rec")</div>"
        local ref_html=""
        [[ -n "$ref" ]] && ref_html="<div class='reference'>Ref: $(html_encode "$ref")</div>"

        findings_html+="<div class='finding'>"
        findings_html+="<div><span class='risk-badge ${risk_class}'>${risk}</span></div>"
        findings_html+="<div class='finding-content'>"
        findings_html+="<h4>$(html_encode "$name")</h4>"
        findings_html+="<p>$(html_encode "$desc")</p>"
        findings_html+="${details_html}${rec_html}${ref_html}"
        findings_html+="</div></div>"
    done <<< "$sorted_findings"
    [[ -n "$prev_cat" ]] && findings_html+="</div></div>"

    cat << HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Mac Security Audit - ${report_hostname}</title>
<style>
:root{--critical:#dc3545;--high:#fd7e14;--medium:#ffc107;--low:#17a2b8;--info:#6c757d;--bg:#f8f9fa;--bg2:#fff;--text:#212529;--text2:#6c757d;--border:#dee2e6}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;padding:20px}
.container{max-width:1200px;margin:0 auto}
.header{background:linear-gradient(135deg,#1e3a5f,#2d5a87);color:#fff;padding:30px;border-radius:12px;margin-bottom:24px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:20px}
.header h1{font-size:28px}
.header-meta{font-size:14px;opacity:.9}
.score-circle{width:120px;height:120px;border-radius:50%;background:conic-gradient(${score_color} ${score}%,#ffffff33 0%);display:flex;align-items:center;justify-content:center}
.score-inner{width:90px;height:90px;border-radius:50%;background:rgba(255,255,255,.95);display:flex;flex-direction:column;align-items:center;justify-content:center;color:var(--text)}
.score-value{font-size:32px;font-weight:700;color:${score_color}}
.score-label{font-size:11px;text-transform:uppercase;letter-spacing:1px}
.summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:24px}
.summary-card{background:var(--bg2);border-radius:10px;padding:20px;text-align:center;box-shadow:0 2px 8px rgba(0,0,0,.08);border-left:4px solid var(--border)}
.summary-card.critical{border-left-color:var(--critical)}.summary-card.high{border-left-color:var(--high)}.summary-card.medium{border-left-color:var(--medium)}.summary-card.low{border-left-color:var(--low)}.summary-card.info{border-left-color:var(--info)}
.summary-card .count{font-size:36px;font-weight:700;margin-bottom:4px}
.summary-card.critical .count{color:var(--critical)}.summary-card.high .count{color:var(--high)}.summary-card.medium .count{color:var(--medium)}.summary-card.low .count{color:var(--low)}.summary-card.info .count{color:var(--info)}
.summary-card .label{font-size:13px;text-transform:uppercase;letter-spacing:1px;color:var(--text2)}
.section{background:var(--bg2);border-radius:10px;margin-bottom:20px;box-shadow:0 2px 8px rgba(0,0,0,.08);overflow:hidden}
.section-header{background:#f1f3f4;padding:16px 20px;font-size:18px;font-weight:600;border-bottom:1px solid var(--border)}
.section-content{padding:0}
.finding{padding:16px 20px;border-bottom:1px solid var(--border);display:grid;grid-template-columns:100px 1fr;gap:16px;align-items:start}
.finding:last-child{border-bottom:none}
.finding:hover{background:#f8f9fa}
.risk-badge{display:inline-block;padding:4px 12px;border-radius:20px;font-size:12px;font-weight:600;text-transform:uppercase;text-align:center}
.risk-critical{background:var(--critical);color:#fff}.risk-high{background:var(--high);color:#fff}.risk-medium{background:var(--medium);color:#212529}.risk-low{background:var(--low);color:#fff}.risk-info{background:var(--info);color:#fff}
.finding-content h4{font-size:15px;font-weight:600;margin-bottom:6px}
.finding-content p{font-size:14px;color:var(--text2);margin-bottom:8px}
.finding-details{background:#f8f9fa;border-radius:6px;padding:10px 14px;font-family:'SF Mono',Menlo,monospace;font-size:12px;white-space:pre-wrap;word-break:break-all;margin-bottom:8px;max-height:150px;overflow-y:auto}
.recommendation{background:#e8f5e9;border-left:3px solid #28a745;padding:8px 12px;font-size:13px;margin-bottom:4px}
.reference{font-size:12px;color:var(--text2)}
.footer{text-align:center;padding:20px;color:var(--text2);font-size:13px}
@media(max-width:768px){.header{flex-direction:column;text-align:center}.finding{grid-template-columns:1fr}}
@media print{body{background:#fff}.section{break-inside:avoid}}
</style>
</head>
<body>
<div class="container">
<header class="header">
<div>
<h1>Mac Security Audit Report</h1>
<div class="header-meta">
<div><strong>Hostname:</strong> ${report_hostname}</div>
<div><strong>Audit Date:</strong> ${AUDIT_DATE}</div>
<div><strong>User:</strong> ${CURRENT_USER}</div>
<div><strong>Tool Version:</strong> ${AUDIT_VERSION}</div>
<div><strong>Platform:</strong> ${OS_NAME} ${OS_VERSION} (${OS_BUILD}) — ${CHIP}</div>
<div><strong>Privileges:</strong> ${admin_badge}</div>
</div>
<button onclick="window.print()" style="background:#6c757d;color:#fff;border:none;padding:8px 18px;border-radius:6px;cursor:pointer;font-size:13px;font-weight:600;margin-top:8px">Print Report</button>
</div>
<div class="score-circle"><div class="score-inner"><div class="score-value">${score_grade}</div><div class="score-label">Score: ${score}</div></div></div>
</header>

<div class="summary-grid">
<div class="summary-card critical"><div class="count">${critical}</div><div class="label">Critical</div></div>
<div class="summary-card high"><div class="count">${high}</div><div class="label">High</div></div>
<div class="summary-card medium"><div class="count">${medium}</div><div class="label">Medium</div></div>
<div class="summary-card low"><div class="count">${low}</div><div class="label">Low</div></div>
<div class="summary-card info"><div class="count">${info}</div><div class="label">Info</div></div>
</div>

${findings_html}

<footer class="footer">
<p>Mac Security Audit Tool v${AUDIT_VERSION} | Generated: ${AUDIT_DATE}</p>
<p>Copyright &copy; Mac O Kay. All rights reserved.</p>
</footer>
</div>
</body>
</html>
HTMLEOF
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

main() {
    if ! $QUIET; then
        cat << 'BANNER'

    +===================================================================+
    |          Mac Security Audit Tool v1.0.0                           |
    |          Copyright (C) Mac O Kay                                  |
    +===================================================================+
    |  Supported: macOS 12 Monterey and later                           |
    |  Recommended: Run with sudo for complete results                  |
    +===================================================================+

BANNER
    fi

    # Platform check
    if [[ "$(uname)" != "Darwin" ]]; then
        echo "ERROR: This tool requires macOS." >&2
        exit 1
    fi

    log INFO "Starting security audit on ${HOSTNAME_RAW}"
    log INFO "Running as: ${CURRENT_USER:-$(whoami)} (root: ${IS_ROOT})"

    # Run all audit modules
    get_system_information
    test_filevault
    test_sip
    test_gatekeeper
    test_firewall
    test_user_accounts
    test_password_policy
    test_screen_lock
    test_sharing_services
    test_mdm_enrollment
    test_updates
    test_xprotect
    test_secure_boot
    test_network_config
    test_disk_security
    test_privacy_settings
    test_find_my_mac
    test_time_machine
    test_software_inventory
    test_remote_access_tools
    test_browser_extensions

    # Generate report
    mkdir -p "$OUTPUT_PATH"

    local report_hostname="$HOSTNAME_RAW"
    $PRIVACY_MODE && report_hostname="REDACTED"
    local timestamp
    timestamp=$(date '+%Y%m%d_%H%M%S')
    local prefix="${REPORT_NAME:-MacSecurityAudit}"
    local report_file="${OUTPUT_PATH}/${prefix}_${report_hostname}_${timestamp}.html"

    generate_html_report > "$report_file"

    log SUCCESS "Audit complete!"
    log INFO "Report saved to: ${report_file}"

    # Summary
    local critical=0 high=0 medium=0 low=0
    for f in "${FINDINGS[@]}"; do
        local risk
        risk=$(echo "$f" | cut -d'|' -f3)
        case "$risk" in
            Critical) ((critical++)) ;;
            High)     ((high++)) ;;
            Medium)   ((medium++)) ;;
            Low)      ((low++)) ;;
        esac
    done

    if ! $QUIET; then
        echo ""
        echo "==================================================================="
        echo "                       AUDIT SUMMARY                               "
        echo "==================================================================="
        echo "  Total Findings: ${#FINDINGS[@]}"
        printf "  Critical: \033[0;31m%d\033[0m\n" "$critical"
        printf "  High:     \033[0;33m%d\033[0m\n" "$high"
        printf "  Medium:   \033[0;33m%d\033[0m\n" "$medium"
        printf "  Low:      \033[0;36m%d\033[0m\n" "$low"
        echo "==================================================================="
        echo ""

        # Try to open report
        if command -v open &>/dev/null; then
            open "$report_file" 2>/dev/null || true
        fi
    fi
}

main "$@"
