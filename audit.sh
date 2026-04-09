#!/usr/bin/env bash
# ============================================================================
# Mac Security Audit Tool v1.0.0
# Copyright (C) 2026 Mac O Kay. Free to use and modify for personal, non-commercial use.
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

# Risk level values for scoring (bash 3.2 compatible)
risk_value() {
    case "$1" in
        Critical) echo 4 ;;
        High)     echo 3 ;;
        Medium)   echo 2 ;;
        Low)      echo 1 ;;
        *)        echo 0 ;;
    esac
}

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
    if [[ -t 1 ]]; then
        local color reset=$'\033[0m'
        case "$level" in
            INFO)    color=$'\033[0;36m' ;;
            WARN)    color=$'\033[0;33m' ;;
            ERROR)   color=$'\033[0;31m' ;;
            SUCCESS) color=$'\033[0;32m' ;;
            *)       color="" ;;
        esac
        printf "%s[%s] [%s] %s%s\n" "$color" "$(date '+%H:%M:%S')" "$level" "$msg" "$reset" >&2
    else
        printf "[%s] [%s] %s\n" "$(date '+%H:%M:%S')" "$level" "$msg" >&2
    fi
}

add_finding() {
    local category="$1" name="$2" risk="$3" description="$4"
    local details="${5:-}" recommendation="${6:-}" reference="${7:-}"
    # Replace real newlines with literal \n so details survive IFS='|' read splitting
    details="${details//$'\n'/\\n}"
    recommendation="${recommendation//$'\n'/\\n}"

    FINDINGS+=("${category}|${name}|${risk}|${description}|${details}|${recommendation}|${reference}")

    if ! $QUIET; then
        if [[ -t 1 ]]; then
            local color reset=$'\033[0m'
            case "$risk" in
                Critical) color=$'\033[0;31m' ;;
                High)     color=$'\033[0;33m' ;;
                Medium)   color=$'\033[0;33m' ;;
                Low)      color=$'\033[0;36m' ;;
                Info)     color=$'\033[0;37m' ;;
                *)        color="" ;;
            esac
            printf "  [%s%s%s] %s\n" "$color" "$(echo "$risk" | tr '[:lower:]' '[:upper:]')" "$reset" "$name" >&2
        else
            printf "  [%s] %s\n" "$(echo "$risk" | tr '[:lower:]' '[:upper:]')" "$name" >&2
        fi
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

    if echo "$fw_stealth" | grep -qiE "enabled|is on"; then
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
    user_count=$(echo "$users" | grep -c . || true)

    # Admin users — exclude system accounts (root, _mbsetupuser, service accounts starting with _)
    local all_admins human_admins
    all_admins=$(dscl . -read /Groups/admin GroupMembership 2>/dev/null | sed 's/GroupMembership: //' || echo "")
    # Filter: keep only accounts with UID >= 500 and not starting with _
    human_admins=""
    for acct in $all_admins; do
        [[ "$acct" == "root" ]] && continue
        [[ "$acct" == _* ]] && continue
        local uid
        uid=$(dscl . -read /Users/"$acct" UniqueID 2>/dev/null | awk '{print $2}')
        [[ -z "$uid" ]] && continue
        [[ "$uid" -lt 500 ]] && continue
        human_admins="${human_admins} ${acct}"
    done
    human_admins=$(echo "$human_admins" | xargs)
    local human_admin_count
    human_admin_count=$(echo "$human_admins" | wc -w | tr -d ' ')

    if [[ "$human_admin_count" -gt 2 ]]; then
        add_finding "User Accounts" "Multiple Admin Accounts" "Medium" \
            "${human_admin_count} human accounts have admin privileges — consider reducing to 1" \
            "Admins: ${human_admins}\n(Excluded system accounts: root, _mbsetupuser)" \
            "Use standard accounts for daily work; reserve admin for one dedicated account" \
            "Principle of Least Privilege"
    else
        add_finding "User Accounts" "Admin Accounts" "Info" \
            "${human_admin_count} human admin account(s)" \
            "Admins: ${human_admins}"
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
    # Note: on macOS Ventura+/Sequoia, absent askForPassword key = enabled (system default)
    local ask_for_pw
    ask_for_pw=$(read_default "com.apple.screensaver" askForPassword "1")
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

    # Display sleep timeout — on macOS Sequoia, screensaver idleTime is deprecated;
    # the lock screen timeout is controlled by display sleep (pmset displaysleep)
    local display_sleep_min
    display_sleep_min=$(pmset -g 2>/dev/null | awk '/displaysleep/{print $2}')
    # Fall back to screensaver idleTime (older macOS)
    if [[ -z "$display_sleep_min" ]]; then
        local idle_time
        idle_time=$(read_default "com.apple.screensaver" idleTime "0")
        display_sleep_min=$(( idle_time / 60 ))
    fi

    if [[ -z "$display_sleep_min" ]] || [[ "$display_sleep_min" -eq 0 ]]; then
        add_finding "Session Security" "Screen Never Sleeps" "Medium" \
            "Display sleep is set to Never — screen will not lock automatically" \
            "displaysleep: Never" \
            "Set display sleep to 10 minutes or less in System Settings > Lock Screen" \
            "CIS Apple macOS Benchmark"
    elif [[ "$display_sleep_min" -gt 15 ]]; then
        add_finding "Session Security" "Long Screen Lock Timeout" "Medium" \
            "Display sleep (and screen lock) is set to more than 15 minutes" \
            "displaysleep: ${display_sleep_min} min" \
            "Reduce to 15 minutes or less: System Settings > Lock Screen" \
            "CIS Apple macOS Benchmark"
    else
        add_finding "Session Security" "Screen Lock Timeout" "Info" \
            "Display sleep set to ${display_sleep_min} minutes" \
            "displaysleep: ${display_sleep_min} min"
    fi

    # Login window settings
    local show_name_password
    show_name_password=$(read_default "/Library/Preferences/com.apple.loginwindow" SHOWFULLNAME "0")
    if [[ "$show_name_password" != "1" ]]; then
        add_finding "Session Security" "Login Window Shows User List" "Low" \
            "Login window displays user list — users can be enumerated without credentials" \
            "SHOWFULLNAME: ${show_name_password}" \
            "On macOS Sequoia, this requires an MDM configuration profile (the defaults write command is ignored). Deploy via Jamf/Intune: com.apple.loginwindow > SHOWFULLNAME = true" \
            "CIS Apple macOS Benchmark"
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

    # Screen Sharing — only flag if system daemon has a live PID (not just agent stubs)
    local vnc_running
    vnc_running=$(launchctl list 2>/dev/null | awk '$3 == "com.apple.screensharing" && $1 != "-" {print 1}')
    if [[ -n "$vnc_running" ]]; then
        add_finding "Sharing" "Screen Sharing Enabled" "Medium" \
            "Screen Sharing (VNC) is running" \
            "" \
            "Disable if not required"
    fi

    # Remote Management (ARD) — check system-level daemon only
    local ard_running
    ard_running=$(launchctl list 2>/dev/null | awk '$3 == "com.apple.RemoteDesktop" && $1 != "-" {print 1}')
    if [[ -n "$ard_running" ]]; then
        add_finding "Sharing" "Remote Management (ARD) Enabled" "Medium" \
            "Apple Remote Desktop agent is running" \
            "" \
            "Disable if not required"
    fi

    # File Sharing (SMB) — only when daemon has live PID
    local smb_running
    smb_running=$(launchctl list 2>/dev/null | awk '$3 == "com.apple.smbd" && $1 != "-" {print 1}')
    if [[ -n "$smb_running" ]]; then
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
        # Check for RMM agents that act as MDM equivalents
        local rmm_agents=""
        [[ -f /Library/LaunchDaemons/com.action1.agent.plist ]] && rmm_agents+="Action1 "
        [[ -d "/Library/Application Support/Jamf" ]] && rmm_agents+="Jamf "
        [[ -f /Library/LaunchDaemons/com.microsoft.intune.agent.plist ]] && rmm_agents+="Intune "
        [[ -f /Library/LaunchDaemons/com.kandji.agent.plist ]] && rmm_agents+="Kandji "
        [[ -f /Library/LaunchDaemons/com.fleetdm.orbit.plist ]] && rmm_agents+="Fleet "

        if [[ -n "$rmm_agents" ]]; then
            add_finding "MDM" "RMM Agent Detected (Not Apple MDM)" "Info" \
                "Device is managed via RMM/agent-based tool — not enrolled in Apple MDM (DEP)" \
                "Agents detected: ${rmm_agents}\nApple MDM: ${profiles_output}" \
                "For full Apple MDM compliance (Activation Lock escrow, remote wipe via MDM), enroll via Apple Business Manager"
        else
            add_finding "MDM" "Device Not MDM Enrolled" "Medium" \
                "This device is not enrolled in MDM or a recognised RMM platform" \
                "$profiles_output" \
                "Enrol in MDM (Jamf, Intune, Kandji) or RMM (Action1) for centralised management"
        fi
    else
        add_finding "MDM" "MDM Status Unknown" "Info" \
            "Could not determine MDM enrollment status" \
            "$profiles_output"
    fi

    # Count installed configuration profiles and gather detail
    local profile_count profiles_raw
    profiles_raw=$(profiles list 2>/dev/null || echo "")
    profile_count=$(echo "$profiles_raw" | grep -c "attribute:" || true)
    if [[ "$profile_count" -gt 0 ]]; then
        local profile_names mdm_server=""
        profile_names=$(echo "$profiles_raw" | awk -F': ' '/name:/{print "  - " $NF}' | head -20)
        if $IS_ROOT; then
            local profiles_xml
            profiles_xml=$(profiles -P -o stdout-xml 2>/dev/null || echo "")
            mdm_server=$(echo "$profiles_xml" | awk -F'[<>]' '/<key>CheckInURL<\/key>/{getline; print $3; exit}')
            [[ -z "$mdm_server" ]] && mdm_server=$(echo "$profiles_xml" | awk -F'[<>]' '/<key>ServerURL<\/key>/{getline; print $3; exit}')
        fi
        local profile_details="Profiles installed: ${profile_count}"
        [[ -n "$mdm_server" ]] && profile_details+="\nMDM Server: ${mdm_server}"
        [[ -n "$profile_names" ]] && profile_details+="\nProfile names:\n${profile_names}"
        add_finding "MDM" "Configuration Profiles Installed" "Info" \
            "${profile_count} configuration profile(s) installed on this device" \
            "$profile_details"
    fi
}

test_updates() {
    log INFO "Checking Software Update Configuration..."

    # Auto update settings
    # Note: AutomaticCheckEnabled may be absent on modern macOS — treat missing key as enabled (system default)
    local auto_check auto_download auto_install auto_system
    auto_check=$(read_default "/Library/Preferences/com.apple.SoftwareUpdate" AutomaticCheckEnabled "1")
    auto_download=$(read_default "/Library/Preferences/com.apple.SoftwareUpdate" AutomaticDownload "0")
    auto_install=$(read_default "/Library/Preferences/com.apple.SoftwareUpdate" AutomaticallyInstallMacOSUpdates "0")
    auto_system=$(read_default "/Library/Preferences/com.apple.SoftwareUpdate" CriticalUpdateInstall "0")

    # Cross-check with plist directly — plutil is more reliable when defaults domain is cached
    if command -v plutil &>/dev/null && [[ -f /Library/Preferences/com.apple.SoftwareUpdate.plist ]]; then
        local plist_check plist_critical
        plist_check=$(plutil -extract AutomaticCheckEnabled raw /Library/Preferences/com.apple.SoftwareUpdate.plist 2>/dev/null || echo "$auto_check")
        plist_critical=$(plutil -extract CriticalUpdateInstall raw /Library/Preferences/com.apple.SoftwareUpdate.plist 2>/dev/null || echo "$auto_system")
        # plutil returns "true"/"false"
        [[ "$plist_check" == "true" ]] && auto_check="1"
        [[ "$plist_check" == "false" ]] && auto_check="0"
        [[ "$plist_critical" == "true" ]] && auto_system="1"
        [[ "$plist_critical" == "false" ]] && auto_system="0"
    fi

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

test_edr_status() {
    log INFO "Checking EDR/Endpoint Security..."

    local launchctl_list
    launchctl_list=$(launchctl list 2>/dev/null)

    # Each entry: "service_name|plist_path|display_name"
    local edr_running="" edr_stopped=""
    local entries=(
        "com.microsoft.fresno|/Library/LaunchDaemons/com.microsoft.fresno.plist|Microsoft Defender"
        "com.crowdstrike.falcond|/Library/LaunchDaemons/com.crowdstrike.falcond.plist|CrowdStrike Falcon"
        "com.sentinelone.sentineld|/Library/LaunchDaemons/com.sentinelone.sentineld.plist|SentinelOne"
        "com.jamf.protect.daemon|/Library/LaunchDaemons/com.jamf.protect.daemon.plist|Jamf Protect"
        "com.paloaltonetworks.cortex.xdr|/Library/LaunchDaemons/com.paloaltonetworks.cortex.xdr.plist|Palo Alto Cortex XDR"
        "com.carbonblack.daemon|/Library/LaunchDaemons/com.carbonblack.daemon.plist|Carbon Black"
        "com.cylance.agent|/Library/LaunchDaemons/com.cylance.agent.plist|Cylance"
    )

    for entry in "${entries[@]}"; do
        local svc="${entry%%|*}"
        local rest="${entry#*|}"
        local plist="${rest%%|*}"
        local display="${rest#*|}"
        if [[ -f "$plist" ]]; then
            local running
            running=$(echo "$launchctl_list" | awk -v s="$svc" '$3==s && $1!="-" {print 1}')
            if [[ -n "$running" ]]; then
                edr_running+="${display}, "
            else
                edr_stopped+="${display}, "
            fi
        fi
    done

    edr_running="${edr_running%, }"
    edr_stopped="${edr_stopped%, }"

    if [[ -n "$edr_running" ]]; then
        local details="Running: ${edr_running}"
        [[ -n "$edr_stopped" ]] && details+="\nInstalled (not running): ${edr_stopped}"
        add_finding "Endpoint Detection & Response" "EDR Active" "Info" \
            "EDR/endpoint security solution is installed and running" \
            "$details"
    elif [[ -n "$edr_stopped" ]]; then
        add_finding "Endpoint Detection & Response" "EDR Installed but Not Running" "Medium" \
            "EDR solution is installed but the system daemon is not active" \
            "Installed (not running): ${edr_stopped}" \
            "Ensure the EDR daemon is enabled: sudo launchctl load -w <plist path>"
    else
        add_finding "Endpoint Detection & Response" "No EDR Solution Detected" "High" \
            "No known EDR or endpoint security solution was detected on this device" \
            "Checked: Microsoft Defender, CrowdStrike Falcon, SentinelOne, Jamf Protect, Palo Alto Cortex XDR, Carbon Black, Cylance" \
            "Deploy an EDR solution appropriate to your organisation (e.g. Microsoft Defender for Endpoint, CrowdStrike Falcon, SentinelOne, or Jamf Protect)" \
            "NIS2 Article 21 — Technical Security Measures"
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
        t2_present=$(system_profiler SPiBridgeDataType 2>/dev/null | grep -c "T2" || true)

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
    vpn_configs=$(scutil --nc list 2>/dev/null | grep -c "VPN" || true)
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

    # On Apple Silicon, nvram does not store FMM token; use Activation Lock status instead
    local activation_lock
    activation_lock=$(system_profiler SPHardwareDataType 2>/dev/null | awk -F': ' '/Activation Lock Status/{print $2}' | xargs)

    # Also check for iCloud account presence (FMM requires Apple ID sign-in)
    local icloud_account
    icloud_account=$(defaults read MobileMeAccounts 2>/dev/null | grep "AccountID" | head -1 | awk -F'"' '{print $2}' || echo "")

    if [[ "$activation_lock" == "Enabled" ]]; then
        add_finding "Device Security" "Find My / Activation Lock Enabled" "Info" \
            "Activation Lock is enabled — device can be remotely locked/wiped" \
            "Activation Lock: ${activation_lock}${icloud_account:+\niCloud: $icloud_account}"
    else
        # Fallback: Intel Macs may store token in nvram
        local fmm_nvram
        fmm_nvram=$(nvram -x -p 2>/dev/null | grep -c "fmm-mobileme-token-FMM" || true)
        if [[ "$fmm_nvram" -gt 0 ]]; then
            add_finding "Device Security" "Find My Mac Enabled" "Info" \
                "Find My Mac token found in NVRAM"
        elif [[ -n "$icloud_account" ]]; then
            add_finding "Device Security" "Find My Mac Status Unclear" "Low" \
                "iCloud account present but Activation Lock not detected — verify Find My is enabled in System Settings" \
                "iCloud: ${icloud_account}" \
                "Enable: System Settings > Apple ID > iCloud > Find My Mac"
        else
            add_finding "Device Security" "Find My Mac Not Detected" "Low" \
                "Find My Mac does not appear to be enabled and no iCloud account detected" \
                "" \
                "Enable Find My Mac for remote lock/wipe capability"
        fi
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

    # Chrome extensions — resolve real names via locale files, exclude Chrome built-ins
    local chrome_ext_dir="$HOME/Library/Application Support/Google/Chrome/Default/Extensions"
    if [[ -d "$chrome_ext_dir" ]]; then
        local chrome_result
        chrome_result=$(python3 -c "
import json, os, glob
chrome_dir = '$chrome_ext_dir'
# Chrome built-in component extension IDs
internals = {'nmmhkkegccagdldgiimedpiccmgmieda', 'mhjfbmdgcfjbbpaeojofohoefgiehjai',
              'pkedcjkdefgpdelpefpick', 'aapocclcgogkmnckokdopfmhonfmgoek'}
names = []
for ext_id in sorted(os.listdir(chrome_dir)):
    if ext_id in ('Temp', '.DS_Store') or ext_id in internals: continue
    ext_path = os.path.join(chrome_dir, ext_id)
    versions = [v for v in os.listdir(ext_path) if os.path.isdir(os.path.join(ext_path, v))]
    if not versions: continue
    mf_path = os.path.join(ext_path, versions[0], 'manifest.json')
    if not os.path.exists(mf_path): continue
    try:
        mf = json.load(open(mf_path))
        name = mf.get('name', ext_id)
        if name.startswith('__MSG_'):
            key = name[6:].rstrip('_')
            locale = mf.get('default_locale', 'en')
            for loc in [locale, 'en', 'en_US']:
                msg_path = os.path.join(ext_path, versions[0], '_locales', loc, 'messages.json')
                if os.path.exists(msg_path):
                    msgs = json.load(open(msg_path))
                    name = (msgs.get(key) or msgs.get(key.lower()) or {}).get('message', ext_id)
                    break
        names.append(name.strip())
    except: names.append(ext_id)
print(str(len(names)))
print('\n'.join(names))
" 2>/dev/null || echo "0")
        local chrome_count; chrome_count=$(echo "$chrome_result" | head -1)
        local chrome_names; chrome_names=$(echo "$chrome_result" | tail -n +2 | tr '\n' '|' | sed 's/|$//')
        chrome_names="${chrome_names//|/$'\n'}"
        if [[ "$chrome_count" -gt 0 ]]; then
            ext_count=$((ext_count + chrome_count))
            add_finding "Browser" "Chrome Extensions" "Info" \
                "${chrome_count} Chrome extension(s) installed" \
                "${chrome_names}"
        fi
    fi

    # Safari — web extensions and content blockers (modern macOS format via pluginkit)
    local safari_web_exts safari_content_blockers
    safari_web_exts=$(pluginkit -m -A -p com.apple.Safari.web-extension 2>/dev/null | sed 's/^ *//' | grep -v "^$" || echo "")
    safari_content_blockers=$(pluginkit -m -A -p com.apple.Safari.content-blocker 2>/dev/null | sed 's/^ *//' | grep -v "^$" || echo "")
    local safari_web_count=0 safari_block_count=0
    [[ -n "$safari_web_exts" ]] && safari_web_count=$(echo "$safari_web_exts" | grep -c . || true)
    [[ -n "$safari_content_blockers" ]] && safari_block_count=$(echo "$safari_content_blockers" | grep -c . || true)
    local safari_total=$(( safari_web_count + safari_block_count ))
    if [[ "$safari_total" -gt 0 ]]; then
        ext_count=$((ext_count + safari_total))
        local safari_lines=""
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            safari_lines+="[Extension] ${line}"$'\n'
        done <<< "$safari_web_exts"
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            safari_lines+="[Content Blocker] ${line}"$'\n'
        done <<< "$safari_content_blockers"
        safari_lines="${safari_lines%$'\n'}"
        add_finding "Browser" "Safari Extensions" "Info" \
            "${safari_total} Safari extension(s)/content blocker(s) installed" \
            "${safari_lines}"
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

test_audit_logging() {
    log INFO "Checking Audit Logging..."

    # BSM/auditd status
    local auditd_running
    auditd_running=$(launchctl list 2>/dev/null | grep -c "com.apple.auditd" || true)
    if [[ "$auditd_running" -gt 0 ]]; then
        add_finding "Logging & Audit" "BSM Audit Daemon Running" "Info" \
            "macOS BSM audit daemon (auditd) is active"
    else
        add_finding "Logging & Audit" "BSM Audit Daemon Not Running" "High" \
            "macOS BSM audit daemon is not active — authentication and privileged events are not logged" \
            "" \
            "Enable: sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist" \
            "NIS2 Article 21 — Logging & Monitoring"
    fi

    # Audit control config
    if [[ -f /etc/security/audit_control ]]; then
        local audit_flags audit_expire
        audit_flags=$(grep "^flags:" /etc/security/audit_control 2>/dev/null || echo "not set")
        audit_expire=$(grep "^expire-after:" /etc/security/audit_control 2>/dev/null || echo "not set")
        add_finding "Logging & Audit" "Audit Configuration Present" "Info" \
            "BSM audit_control is configured" \
            "${audit_flags}\n${audit_expire}"
    else
        add_finding "Logging & Audit" "Audit Configuration Missing" "High" \
            "/etc/security/audit_control not found — BSM audit logging is not configured" \
            "" \
            "Restore default config: sudo cp /etc/security/audit_control.example /etc/security/audit_control 2>/dev/null || sudo sh -c 'printf \"dir:/var/audit\nflags:lo,aa,ad\nminfree:5\nnaflags:lo,aa\npolicy:cnt,argv\nfilesz:2M\nexpire-after:60d\nsupervisor-count:0\n\" > /etc/security/audit_control' && sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist" \
            "CIS macOS Benchmark 3.2"
    fi

    # Audit log storage
    if [[ -d /var/audit ]]; then
        local audit_size
        audit_size=$(du -sh /var/audit 2>/dev/null | cut -f1 || echo "unknown")
        add_finding "Logging & Audit" "Audit Log Storage" "Info" \
            "Audit logs present in /var/audit" \
            "Approx size: ${audit_size}"
    fi

    # Remote log forwarding / SIEM readiness
    local siem_found=false
    if ls /etc/asl/*.conf 2>/dev/null | xargs grep -l "^>" 2>/dev/null | grep -q . 2>/dev/null; then
        siem_found=true
    fi
    if [[ -f /etc/syslog.conf ]] && grep -q "@" /etc/syslog.conf 2>/dev/null; then
        siem_found=true
    fi
    if $siem_found; then
        add_finding "Logging & Audit" "Remote Log Forwarding Configured" "Info" \
            "Remote syslog/SIEM forwarding appears to be configured"
    else
        add_finding "Logging & Audit" "No Remote Log Forwarding" "Medium" \
            "No remote syslog/SIEM forwarding detected" \
            "" \
            "Configure log forwarding to SIEM for centralised incident detection" \
            "NIS2 Article 21 — Logging"
    fi
}

test_siem_forwarding() {
    log INFO "Checking SIEM/Log Forwarder..."

    local launchctl_list
    launchctl_list=$(launchctl list 2>/dev/null)

    local forwarders_running="" forwarders_stopped=""

    # Splunk Universal Forwarder
    if [[ -d "/Applications/SplunkForwarder" ]] || [[ -f "/Library/LaunchDaemons/com.splunk.plist" ]]; then
        local r; r=$(echo "$launchctl_list" | awk '$3=="com.splunk" && $1!="-" {print 1}')
        [[ -n "$r" ]] && forwarders_running+="Splunk UF, " || forwarders_stopped+="Splunk UF, "
    fi

    # osquery
    if [[ -f "/usr/local/bin/osqueryd" ]] || [[ -f "/Library/LaunchDaemons/com.facebook.osqueryd.plist" ]]; then
        local r; r=$(echo "$launchctl_list" | awk '$3=="com.facebook.osqueryd" && $1!="-" {print 1}')
        [[ -n "$r" ]] && forwarders_running+="osquery, " || forwarders_stopped+="osquery, "
    fi

    # Elastic Agent
    if [[ -f "/Library/LaunchDaemons/co.elastic.elastic-agent.plist" ]]; then
        local r; r=$(echo "$launchctl_list" | awk '$3=="co.elastic.elastic-agent" && $1!="-" {print 1}')
        [[ -n "$r" ]] && forwarders_running+="Elastic Agent, " || forwarders_stopped+="Elastic Agent, "
    fi

    # Filebeat
    if command -v filebeat &>/dev/null || [[ -f "/usr/local/bin/filebeat" ]]; then
        forwarders_running+="Filebeat, "
    fi

    # Microsoft Defender DLP/telemetry sensor
    if [[ -f "/Library/LaunchDaemons/com.microsoft.dlp.daemon.plist" ]]; then
        local r; r=$(echo "$launchctl_list" | awk '$3=="com.microsoft.dlp.daemon" && $1!="-" {print 1}')
        [[ -n "$r" ]] && forwarders_running+="Microsoft Defender Telemetry, " || forwarders_stopped+="Microsoft Defender Telemetry, "
    fi

    forwarders_running="${forwarders_running%, }"
    forwarders_stopped="${forwarders_stopped%, }"

    if [[ -n "$forwarders_running" ]]; then
        local details="Active: ${forwarders_running}"
        [[ -n "$forwarders_stopped" ]] && details+="\nInactive: ${forwarders_stopped}"
        details+="\nNote: Detection is presence-only — verify data flow in your SIEM console."
        add_finding "Logging & Audit" "Log Forwarder Active" "Info" \
            "SIEM/log forwarding agent is installed and running" \
            "$details" \
            "" \
            "NIS2 Article 21 — Logging & Monitoring"
    elif [[ -n "$forwarders_stopped" ]]; then
        add_finding "Logging & Audit" "Log Forwarder Installed but Inactive" "Low" \
            "A SIEM log forwarding agent is installed but not currently running" \
            "Installed (not running): ${forwarders_stopped}\nNote: Detection is presence-only — verify configuration." \
            "Ensure the log forwarder service is enabled and configured to send to your SIEM" \
            "NIS2 Article 21 — Logging & Monitoring"
    else
        add_finding "Logging & Audit" "No SIEM Log Forwarder Detected" "Medium" \
            "No known SIEM or log forwarding agent was detected on this device" \
            "Checked: Splunk Universal Forwarder, osquery, Elastic Agent, Filebeat, Microsoft Defender Telemetry\nNote: Detection is presence-only — verify data flow in your SIEM console." \
            "Deploy a log forwarding agent (Splunk UF, Elastic Agent, or osquery) to centralise endpoint logs in your SIEM" \
            "NIS2 Article 21 — Logging & Monitoring"
    fi
}

test_tcc_permissions() {
    log INFO "Checking TCC Privacy Permissions..."

    local tcc_db=""
    if $IS_ROOT && [[ -f "/Library/Application Support/com.apple.TCC/TCC.db" ]]; then
        tcc_db="/Library/Application Support/com.apple.TCC/TCC.db"
    elif [[ -f "$HOME/Library/Application Support/com.apple.TCC/TCC.db" ]]; then
        tcc_db="$HOME/Library/Application Support/com.apple.TCC/TCC.db"
    fi

    if [[ -z "$tcc_db" ]]; then
        add_finding "Privacy & TCC" "TCC Database Not Accessible" "Info" \
            "TCC database not accessible — re-run with sudo for full results"
        return
    fi

    if ! command -v sqlite3 &>/dev/null; then
        add_finding "Privacy & TCC" "sqlite3 Not Available" "Info" \
            "Cannot query TCC database — sqlite3 not found"
        return
    fi

    local tcc_result
    tcc_result=$(sqlite3 "$tcc_db" "SELECT service, client, auth_value FROM access WHERE auth_value=1;" 2>/dev/null || echo "")

    if [[ -z "$tcc_result" ]]; then
        add_finding "Privacy & TCC" "TCC Database Protected by SIP" "Info" \
            "TCC database is protected by System Integrity Protection — privacy permissions cannot be read from the command line" \
            "Source: $(basename "$tcc_db")\nThis is expected behaviour on macOS with SIP enabled. Use System Settings > Privacy & Security to review app permissions manually."
        return
    fi

    # Full Disk Access
    local fda_apps
    fda_apps=$(echo "$tcc_result" | grep "kTCCServiceSystemPolicySysAdminFiles\|kTCCServiceSystemPolicyAllFiles" | awk -F'|' '{print $2}' | sort -u | tr '\n' ', ' | sed 's/,$//')
    if [[ -n "$fda_apps" ]]; then
        add_finding "Privacy & TCC" "Full Disk Access Granted" "Medium" \
            "Apps with Full Disk Access can read all files on this Mac" \
            "$fda_apps" \
            "Revoke Full Disk Access for any app that doesn't strictly require it" \
            "CIS macOS Benchmark 6.3"
    else
        add_finding "Privacy & TCC" "Full Disk Access" "Info" \
            "No apps with Full Disk Access detected in queried TCC database"
    fi

    # Accessibility / Automation (can control other apps — high-value malware target)
    local acc_apps
    acc_apps=$(echo "$tcc_result" | grep "kTCCServiceAccessibility\|kTCCServiceAutomation" | awk -F'|' '{print $2}' | sort -u | tr '\n' ', ' | sed 's/,$//')
    if [[ -n "$acc_apps" ]]; then
        add_finding "Privacy & TCC" "Accessibility/Automation Access" "Low" \
            "Apps with accessibility or automation permissions can control other apps" \
            "$acc_apps" \
            "Review and revoke any unexpected entries"
    fi

    # Camera
    local cam_apps
    cam_apps=$(echo "$tcc_result" | grep "kTCCServiceCamera" | awk -F'|' '{print $2}' | sort -u | tr '\n' ', ' | sed 's/,$//')
    [[ -n "$cam_apps" ]] && add_finding "Privacy & TCC" "Camera Access Granted" "Info" \
        "Apps with camera permission" "$cam_apps"

    # Microphone
    local mic_apps
    mic_apps=$(echo "$tcc_result" | grep "kTCCServiceMicrophone" | awk -F'|' '{print $2}' | sort -u | tr '\n' ', ' | sed 's/,$//')
    [[ -n "$mic_apps" ]] && add_finding "Privacy & TCC" "Microphone Access Granted" "Info" \
        "Apps with microphone permission" "$mic_apps"

    add_finding "Privacy & TCC" "TCC Summary" "Info" \
        "TCC database queried — privacy permissions reviewed" \
        "Source: $(basename "$tcc_db")"
}

test_system_extensions() {
    log INFO "Checking System & Kernel Extensions..."

    # System extensions (modern macOS)
    if command -v systemextensionsctl &>/dev/null; then
        local sysext_out
        sysext_out=$(systemextensionsctl list 2>/dev/null || echo "")
        if [[ -n "$sysext_out" ]]; then
            local sysext_count
            sysext_count=$(echo "$sysext_out" | grep -c "enabled activated" || true)
            add_finding "System Extensions" "Active System Extensions" "Info" \
                "${sysext_count} enabled system extension(s)" \
                "$sysext_out"
        fi
    fi

    # Legacy kernel extensions — deprecated, elevated kernel privilege
    local third_party_kexts
    third_party_kexts=$(kextstat 2>/dev/null | grep -v "com.apple" | tail -n +2 || echo "")
    if [[ -n "$third_party_kexts" ]]; then
        local kext_count
        kext_count=$(echo "$third_party_kexts" | grep -c . || true)
        add_finding "System Extensions" "Third-Party Kernel Extensions" "Medium" \
            "${kext_count} third-party kext(s) loaded — runs in kernel with full system privilege" \
            "$third_party_kexts" \
            "Verify each kext is from a trusted vendor; kexts are deprecated in macOS 12+" \
            "CIS macOS Benchmark"
    else
        add_finding "System Extensions" "No Third-Party Kernel Extensions" "Info" \
            "No third-party kernel extensions detected"
    fi

    # Third-party launch agents/daemons (persistence mechanisms)
    local user_agents sys_agents sys_daemons
    user_agents=$(ls -1 "$HOME/Library/LaunchAgents" 2>/dev/null | grep -v "^com\.apple" || echo "")
    sys_agents=$(ls -1 /Library/LaunchAgents 2>/dev/null | grep -v "^com\.apple" || echo "")
    sys_daemons=$(ls -1 /Library/LaunchDaemons 2>/dev/null | grep -v "^com\.apple" || echo "")

    local agent_count=0
    [[ -n "$user_agents" ]] && agent_count=$(( agent_count + $(echo "$user_agents" | grep -c . || true) ))
    [[ -n "$sys_agents" ]] && agent_count=$(( agent_count + $(echo "$sys_agents" | grep -c . || true) ))
    [[ -n "$sys_daemons" ]] && agent_count=$(( agent_count + $(echo "$sys_daemons" | grep -c . || true) ))

    if [[ "$agent_count" -gt 0 ]]; then
        local agents_combined=""
        [[ -n "$user_agents" ]] && agents_combined+="~/Library/LaunchAgents:\n${user_agents}\n"
        [[ -n "$sys_agents" ]] && agents_combined+="/Library/LaunchAgents:\n${sys_agents}\n"
        [[ -n "$sys_daemons" ]] && agents_combined+="/Library/LaunchDaemons:\n${sys_daemons}"
        add_finding "System Extensions" "Third-Party Launch Agents/Daemons" "Low" \
            "${agent_count} non-Apple launch agent(s)/daemon(s) — auto-start on login" \
            "$agents_combined" \
            "Review each entry for legitimacy; these are common persistence mechanisms"
    else
        add_finding "System Extensions" "No Third-Party Launch Agents" "Info" \
            "No non-Apple launch agents or daemons detected"
    fi
}

test_authentication() {
    log INFO "Checking Authentication & Biometrics..."

    # Touch ID enrollment — bioutil requires a user session; not available under root
    if command -v bioutil &>/dev/null; then
        if $IS_ROOT; then
            # bioutil -c fails as root (requires GUI session context)
            local tid_sys_enabled
            tid_sys_enabled=$(bioutil -s -r 2>/dev/null | awk -F': ' '/Biometrics functionality/{print $2}' | xargs)
            if [[ "$tid_sys_enabled" == "0" ]]; then
                add_finding "Authentication" "Touch ID Disabled System-Wide" "Medium" \
                    "Touch ID functionality is disabled at the system level" \
                    "" \
                    "Enable: System Settings > Touch ID & Password"
            else
                add_finding "Authentication" "Touch ID Status" "Info" \
                    "Touch ID is enabled system-wide — per-user enrollment not checkable under root" \
                    "Re-run without sudo to verify individual fingerprint enrollment"
            fi
        else
            local tid_count tid_enabled
            tid_count=$(bioutil -c 2>/dev/null | awk '/biometric template/{sum+=$3} END{print sum+0}')
            tid_enabled=$(bioutil -s -r 2>/dev/null | awk -F': ' '/Biometrics functionality/{print $2}' | xargs)

            if [[ "$tid_enabled" == "0" ]]; then
                add_finding "Authentication" "Touch ID Disabled System-Wide" "Medium" \
                    "Touch ID functionality is disabled at the system level" \
                    "" \
                    "Enable: System Settings > Touch ID & Password"
            elif [[ "$tid_count" -gt 0 ]]; then
                add_finding "Authentication" "Touch ID Enrolled" "Info" \
                    "Touch ID is configured — ${tid_count} fingerprint(s) enrolled for current user"
            else
                add_finding "Authentication" "Touch ID Not Configured" "Low" \
                    "Touch ID is available but no fingerprints enrolled for current user" \
                    "" \
                    "Enroll fingerprints: System Settings > Touch ID & Password"
            fi
        fi
    fi

    # Password hint exposure
    local hint_retries
    hint_retries=$(read_default "/Library/Preferences/com.apple.loginwindow" RetriesUntilHint "0")
    if [[ "$hint_retries" -gt 0 ]]; then
        add_finding "Authentication" "Password Hints Enabled" "Low" \
            "Login window displays password hints after ${hint_retries} failed attempt(s)" \
            "RetriesUntilHint: $hint_retries" \
            "Disable: sudo defaults write /Library/Preferences/com.apple.loginwindow RetriesUntilHint 0"
    else
        add_finding "Authentication" "Password Hints Disabled" "Info" \
            "Login window does not display password hints"
    fi

    # Firmware password (Intel) / Secure Enclave note (Apple Silicon)
    if [[ "$IS_APPLE_SILICON" == "true" ]]; then
        add_finding "Authentication" "Apple Silicon Boot Protection" "Info" \
            "Secure Enclave protects boot process; Activation Lock enforced via Apple ID / MDM" \
            "" \
            "Ensure device is enrolled in MDM with Activation Lock enabled"
    else
        local fw_check
        fw_check=$(firmwarepasswd -check 2>/dev/null || echo "unknown")
        if echo "$fw_check" | grep -q "Yes"; then
            add_finding "Authentication" "Firmware Password Set (Intel)" "Info" \
                "EFI firmware password is configured — single-user mode is protected"
        else
            add_finding "Authentication" "No Firmware Password (Intel)" "Medium" \
                "EFI firmware password is not set — boot options and single-user mode are accessible" \
                "" \
                "Set firmware password: sudo firmwarepasswd -setpasswd" \
                "CIS macOS Benchmark 3.1.4"
        fi
    fi

    # Developer tools security relaxation
    local devtools_status
    devtools_status=$(DevToolsSecurity -status 2>/dev/null || echo "")
    if echo "$devtools_status" | grep -qi "enabled"; then
        add_finding "Authentication" "Developer Tools Security Relaxed" "Low" \
            "DevToolsSecurity is enabled — debug APIs and DTrace are accessible without sudo" \
            "$devtools_status" \
            "Disable if not a developer machine: sudo DevToolsSecurity -disable"
    fi
}

test_firewall_advanced() {
    log INFO "Checking Firewall Logging & Advanced Settings..."

    local fw_bin="/usr/libexec/ApplicationFirewall/socketfilterfw"
    [[ ! -x "$fw_bin" ]] && return

    # Firewall logging — checked via ALF plist (socketfilterfw --getloggingmode removed in macOS 12+)
    local fw_log_enabled
    fw_log_enabled=$(defaults read /Library/Preferences/com.apple.alf loggingenabled 2>/dev/null || echo "0")
    if [[ "$fw_log_enabled" == "1" ]]; then
        add_finding "Firewall" "Firewall Logging Enabled" "Info" \
            "Application Firewall logging is active — blocked connections are recorded"
    else
        add_finding "Firewall" "Firewall Logging Disabled" "Low" \
            "Firewall logging is not enabled — blocked connections leave no audit trail" \
            "loggingenabled: ${fw_log_enabled}" \
            "Enable via: sudo defaults write /Library/Preferences/com.apple.alf loggingenabled -int 1" \
            "NIS2 Article 21 — Logging"
    fi

    # Block all incoming
    local fw_block_all
    fw_block_all=$("$fw_bin" --getblockall 2>/dev/null || echo "")
    if echo "$fw_block_all" | grep -qi "enabled"; then
        add_finding "Firewall" "Block All Mode Active" "Info" \
            "Firewall is set to block all incoming connections"
    fi
}

test_network_security_advanced() {
    log INFO "Checking Advanced Network Security..."

    # Web proxy (potential MITM)
    local http_proxy https_proxy
    http_proxy=$(networksetup -getwebproxy Wi-Fi 2>/dev/null | grep "Enabled: Yes" || echo "")
    https_proxy=$(networksetup -getsecurewebproxy Wi-Fi 2>/dev/null | grep "Enabled: Yes" || echo "")
    if [[ -n "$http_proxy" ]] || [[ -n "$https_proxy" ]]; then
        add_finding "Network" "Web Proxy Configured" "Medium" \
            "A web proxy is active on Wi-Fi — all HTTP/S traffic is routed through it" \
            "HTTP: ${http_proxy:-disabled}\nHTTPS: ${https_proxy:-disabled}" \
            "Verify this is a corporate proxy and not malicious injection"
    fi

    # Bluetooth
    local bt_state
    bt_state=$(defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState 2>/dev/null || echo "unknown")
    if [[ "$bt_state" == "1" ]]; then
        add_finding "Network" "Bluetooth Enabled" "Info" \
            "Bluetooth is active — additional wireless attack surface"
    elif [[ "$bt_state" == "0" ]]; then
        add_finding "Network" "Bluetooth Disabled" "Info" \
            "Bluetooth is disabled"
    fi

    # mDNS/Bonjour — check if multicast advertisements are suppressed
    local mdns_suppressed
    mdns_suppressed=$(defaults read /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements 2>/dev/null || echo "0")
    if [[ "$mdns_suppressed" == "1" ]] || [[ "$mdns_suppressed" == "true" ]]; then
        add_finding "Network" "mDNS Multicast Ads Suppressed" "Info" \
            "Bonjour multicast advertisements are disabled (NoMulticastAdvertisements = true)"
    else
        add_finding "Network" "mDNS/Bonjour Advertising Active" "Low" \
            "Bonjour is advertising this device on the local network — exposes device info to peers" \
            "NoMulticastAdvertisements: not set" \
            "Suppress: sudo defaults write /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements -bool true"
    fi

    # iCloud Private Relay
    local private_relay
    private_relay=$(defaults read com.apple.networkd private-relay-enabled 2>/dev/null || echo "")
    if [[ "$private_relay" == "1" ]]; then
        add_finding "Network" "iCloud Private Relay Enabled" "Info" \
            "iCloud Private Relay routes Safari/DNS traffic via Apple relays for privacy"
    fi

    # Check for suspicious network locations
    local net_locations
    net_locations=$(networksetup -listlocations 2>/dev/null || echo "")
    local loc_count
    loc_count=$(echo "$net_locations" | grep -c . || true)
    if [[ "$loc_count" -gt 1 ]]; then
        add_finding "Network" "Multiple Network Locations" "Info" \
            "${loc_count} network location profiles configured" \
            "$net_locations"
    fi
}

# ============================================================================
# HTML REPORT GENERATION
# ============================================================================

generate_html_report() {
    log INFO "Generating HTML Report..."

    local critical=0 high=0 medium=0 low=0 info=0
    for f in "${FINDINGS[@]}"; do
        local firstline="${f%%$'\n'*}"
        local after_cat="${firstline#*|}"
        local after_name="${after_cat#*|}"
        local risk="${after_name%%|*}"
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
    # Use parameter expansion (not echo) to safely extract fields from multi-line details
    local sorted_findings
    sorted_findings=$(for i in "${!FINDINGS[@]}"; do
        local f="${FINDINGS[$i]}"
        # Extract cat and risk from first line only — avoids newlines in details corrupting sort
        local firstline="${f%%$'\n'*}"
        local cat="${firstline%%|*}"
        local after_cat="${firstline#*|}"
        local after_name="${after_cat#*|}"
        local risk="${after_name%%|*}"
        local rv; rv=$(risk_value "$risk")
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
            findings_html+="<div class='section' id='${cat_id}' data-category='${cat_id}'>"
            findings_html+="<div class='section-header' onclick='toggleSection(this)'><span>$(html_encode "$cat")</span><span class='chevron'>&#9660;</span></div>"
            findings_html+="<div class='section-content'>"
            prev_cat="$cat"
        fi

        local risk_class="risk-$(echo "$risk" | tr '[:upper:]' '[:lower:]')"
        local details_html=""
        if [[ -n "$details" ]]; then
            local details_encoded
            details_encoded=$(html_encode "$details")
            details_encoded="${details_encoded//\\n/<br>}"
            details_html="<div class='finding-details'>${details_encoded}</div>"
        fi
        local rec_html=""
        if [[ -n "$rec" ]]; then
            local rec_encoded
            rec_encoded=$(html_encode "$rec")
            rec_encoded="${rec_encoded//\\n/<br>}"
            rec_html="<div class='recommendation'>${rec_encoded}</div>"
        fi
        local ref_html=""
        [[ -n "$ref" ]] && ref_html="<div class='reference'>Ref: $(html_encode "$ref")</div>"

        findings_html+="<div class='finding' data-risk='$(echo "$risk" | tr '[:upper:]' '[:lower:]')'>"
        findings_html+="<div><span class='risk-badge ${risk_class}'>${risk}</span></div>"
        findings_html+="<div class='finding-content'>"
        findings_html+="<h4>$(html_encode "$name")</h4>"
        findings_html+="<p>$(html_encode "$desc")</p>"
        findings_html+="${details_html}${rec_html}${ref_html}"
        findings_html+="</div></div>"
    done <<< "$sorted_findings"
    [[ -n "$prev_cat" ]] && findings_html+="</div></div>"

    # --- Cyber Essentials: compute pass/fail from FINDINGS ---
    local ce_fw="pass" ce_fw_notes=""
    local ce_sc="pass" ce_sc_notes=""
    local ce_ac="pass" ce_ac_notes=""
    local ce_mp="pass" ce_mp_notes=""
    local ce_pm="pass" ce_pm_notes=""

    for f in "${FINDINGS[@]}"; do
        local firstline="${f%%$'\n'*}"
        local cat="${firstline%%|*}"
        local after_cat="${firstline#*|}"
        local fname="${after_cat%%|*}"
        local after_name="${after_cat#*|}"
        local frisk="${after_name%%|*}"

        case "$fname" in
            "Application Firewall Disabled")       ce_fw="fail";   ce_fw_notes+="[FAIL] Firewall disabled<br>" ;;
            "Application Firewall Enabled")        ce_fw_notes+="[OK] Firewall enabled<br>" ;;
            "Stealth Mode Enabled")                ce_fw_notes+="[OK] Stealth mode on<br>" ;;
            "Stealth Mode Disabled")               [[ "$ce_fw" != "fail" ]] && ce_fw="review"; ce_fw_notes+="[WARN] Stealth mode off<br>" ;;
            "Firewall Logging Enabled")            ce_fw_notes+="[OK] Firewall logging on<br>" ;;
            "Firewall Logging Disabled")           ce_fw_notes+="[WARN] Firewall logging off<br>" ;;
            "SIP Enabled")                         ce_sc_notes+="[OK] SIP enabled<br>" ;;
            "SIP Disabled"|"SIP Status Unknown")   ce_sc="fail"; ce_sc_notes+="[FAIL] SIP disabled<br>" ;;
            "Gatekeeper Enabled")                  ce_sc_notes+="[OK] Gatekeeper enabled<br>" ;;
            "Gatekeeper Disabled")                 ce_sc="fail"; ce_sc_notes+="[FAIL] Gatekeeper disabled<br>" ;;
            "Device is MDM Enrolled"|"RMM Agent Detected"*) ce_sc_notes+="[OK] Managed endpoint<br>" ;;
            "Device Not MDM Enrolled")             [[ "$ce_sc" != "fail" ]] && ce_sc="review"; ce_sc_notes+="[WARN] No MDM/RMM<br>" ;;
            "Auto-Login Disabled")                 ce_ac_notes+="[OK] Auto-login disabled<br>" ;;
            "Auto-Login Enabled")                  ce_ac="fail"; ce_ac_notes+="[FAIL] Auto-login enabled<br>" ;;
            "Guest Account Disabled")              ce_ac_notes+="[OK] Guest account disabled<br>" ;;
            "Guest Account Enabled")               ce_ac="fail"; ce_ac_notes+="[FAIL] Guest account enabled<br>" ;;
            "Password on Wake")                    ce_ac_notes+="[OK] Password required on wake<br>" ;;
            "No Password on Wake")                 ce_ac="fail"; ce_ac_notes+="[FAIL] No password on wake<br>" ;;
            "Admin Accounts")                      ce_ac_notes+="[OK] Admin accounts reviewed<br>" ;;
            "Multiple Admin Accounts")             [[ "$ce_ac" != "fail" ]] && ce_ac="review"; ce_ac_notes+="[WARN] Multiple admins<br>" ;;
            "XProtect Active")                     ce_mp_notes+="[OK] XProtect active<br>" ;;
            "XProtect Remediator Present")         ce_mp_notes+="[OK] XProtect Remediator active<br>" ;;
            "Automatic Updates Configured")        ce_pm_notes+="[OK] Auto-updates enabled<br>" ;;
            "Automatic Update Check Disabled")     ce_pm="fail"; ce_pm_notes+="[FAIL] Auto-update check off<br>" ;;
            "Critical Updates Not Auto-Installed") [[ "$ce_pm" != "fail" ]] && ce_pm="review"; ce_pm_notes+="[WARN] Critical updates not auto-installed<br>" ;;
            "macOS Version Supported")             ce_pm_notes+="[OK] macOS version current<br>" ;;
            "Older macOS Version")                 [[ "$ce_pm" != "fail" ]] && ce_pm="review"; ce_pm_notes+="[WARN] Older macOS<br>" ;;
            "Unsupported macOS Version")           ce_pm="fail"; ce_pm_notes+="[FAIL] Unsupported macOS<br>" ;;
        esac
    done

    # CE readiness score
    local ce_pass=0
    [[ "$ce_fw" == "pass" ]] && ((ce_pass++))
    [[ "$ce_sc" == "pass" ]] && ((ce_pass++))
    [[ "$ce_ac" == "pass" ]] && ((ce_pass++))
    [[ "$ce_mp" == "pass" ]] && ((ce_pass++))
    [[ "$ce_pm" == "pass" ]] && ((ce_pass++))
    local ce_pct=$(( ce_pass * 100 / 5 ))

    ce_fw_notes="${ce_fw_notes%<br>}"
    ce_sc_notes="${ce_sc_notes%<br>}"
    ce_ac_notes="${ce_ac_notes%<br>}"
    ce_mp_notes="${ce_mp_notes%<br>}"
    ce_pm_notes="${ce_pm_notes%<br>}"

    # --- Helper: check if a finding with given name exists ---
    finding_exists() {
        local target="$1" f after_cat name
        for f in "${FINDINGS[@]}"; do
            after_cat="${f#*|}"
            name="${after_cat%%|*}"
            [[ "$name" == "$target" ]] && return 0
        done
        return 1
    }

    # --- Next Steps: Critical + High findings sorted by risk desc, max 10 ---
    local next_steps_html="" ns_count=0
    local ns_sorted
    ns_sorted=$(for i in "${!FINDINGS[@]}"; do
        local f="${FINDINGS[$i]}"
        local firstline="${f%%$'\n'*}"
        local after_cat="${firstline#*|}"
        local risk="${after_cat#*|}"; risk="${risk%%|*}"
        local rv; rv=$(risk_value "$risk")
        printf "%s\t%s\n" "$rv" "$i"
    done | sort -t$'\t' -k1,1rn)

    while IFS=$'\t' read -r rv idx; do
        [[ $ns_count -ge 10 ]] && break
        local f="${FINDINGS[$idx]}"
        local firstline="${f%%$'\n'*}"
        local after_cat="${firstline#*|}"
        local risk="${after_cat#*|}"; risk="${risk%%|*}"
        [[ "$risk" != "Critical" ]] && [[ "$risk" != "High" ]] && break
        local name="${after_cat%%|*}"
        local _c _n _r _d _det rec _ref
        IFS='|' read -r _c _n _r _d _det rec _ref <<< "$firstline"
        local risk_lower; risk_lower=$(echo "$risk" | tr '[:upper:]' '[:lower:]')
        next_steps_html+="<div class='ns-item'>"
        next_steps_html+="<span class='risk-badge risk-${risk_lower}'>${risk}</span>"
        next_steps_html+="<div class='ns-content'><strong>$(html_encode "$name")</strong>"
        [[ -n "$rec" ]] && next_steps_html+="<div class='ns-rec'>$(html_encode "$rec")</div>"
        next_steps_html+="</div></div>"
        ((ns_count++)) || true
    done <<< "$ns_sorted"
    if [[ $ns_count -eq 0 ]]; then
        next_steps_html="<p class='ns-none'>No Critical or High findings — good security posture.</p>"
    fi

    # --- CIS Benchmark Level 1 Mapping (macOS) ---
    local cis_html="" cis_pass=0 cis_fail=0 cis_unknown=0

    cis_row() {
        local cis_id="$1" label="$2" pass_name="$3" fail_name="$4"
        local status="unknown"
        if [[ -n "$fail_name" ]] && finding_exists "$fail_name"; then
            status="fail"; ((cis_fail++)) || true
        elif [[ -n "$pass_name" ]] && finding_exists "$pass_name"; then
            status="pass"; ((cis_pass++)) || true
        else
            # absence-of-fail = pass for controls where negative finding is always emitted
            if [[ -z "$pass_name" ]] && [[ -n "$fail_name" ]]; then
                status="pass"; ((cis_pass++)) || true
            else
                ((cis_unknown++)) || true
            fi
        fi
        local badge_class="review"
        [[ "$status" == "pass" ]] && badge_class="pass"
        [[ "$status" == "fail" ]] && badge_class="fail"
        cis_html+="<tr><td class='cis-id'>${cis_id}</td><td>${label}</td>"
        cis_html+="<td><span class='ce-status ${badge_class}'>$(echo "$status" | tr '[:lower:]' '[:upper:]')</span></td></tr>"
    }

    cis_row "1.1"   "Software Update checks enabled"     "Automatic Updates Configured"       "Automatic Update Check Disabled"
    cis_row "2.1"   "FileVault disk encryption enabled"  "FileVault Enabled"                  "FileVault Disabled"
    cis_row "2.2"   "Gatekeeper enabled"                 "Gatekeeper Enabled"                 "Gatekeeper Disabled"
    cis_row "2.3"   "System Integrity Protection enabled" "SIP Enabled"                       "SIP Disabled"
    cis_row "2.4.1" "Application firewall enabled"       "Application Firewall Enabled"       "Application Firewall Disabled"
    cis_row "2.4.2" "Stealth mode enabled"               "Stealth Mode Enabled"               "Stealth Mode Disabled"
    cis_row "2.5"   "Password required on wake"          "Password on Wake"                   "No Password on Wake"
    cis_row "2.6"   "Screen lock timeout ≤ 20 min"       ""                                   "Screen Never Sleeps"
    cis_row "2.7"   "Auto-login disabled"                "Auto-Login Disabled"                "Auto-Login Enabled"
    cis_row "2.8"   "Guest account disabled"             "Guest Account Disabled"             "Guest Account Enabled"
    cis_row "3.1"   "Remote login (SSH) disabled"        "Remote Login (SSH) Disabled"        "Remote Login (SSH) Enabled"
    cis_row "3.2"   "File sharing disabled"              ""                                   "File Sharing (SMB) Enabled"
    cis_row "3.3"   "Screen sharing disabled"            ""                                   "Screen Sharing Enabled"
    cis_row "4.1"   "BSM audit daemon running"           "BSM Audit Daemon Running"           "BSM Audit Daemon Not Running"
    cis_row "4.2"   "Audit configuration present"        "Audit Configuration Present"        "Audit Configuration Missing"
    cis_row "5.1"   "Touch ID configured"                "Touch ID Enrolled"                  "Touch ID Not Configured"
    cis_row "5.2"   "Time Machine backup configured"     "Time Machine Configured"            "No Time Machine Backup"
    cis_row "6.1"   "EDR/endpoint security active"       "EDR Active"                         "No EDR Solution Detected"

    local cis_total=$(( cis_pass + cis_fail + cis_unknown ))
    local cis_pct=0
    [[ $cis_total -gt 0 ]] && cis_pct=$(( cis_pass * 100 / cis_total ))

    # --- TOC: collect unique categories in sorted order ---
    local toc_html=""
    local toc_cats
    toc_cats=$(for f in "${FINDINGS[@]}"; do
        local firstline="${f%%$'\n'*}"
        echo "${firstline%%|*}"
    done | sort -u)
    while IFS= read -r tcat; do
        [[ -z "$tcat" ]] && continue
        local tid; tid=$(echo "$tcat" | tr ' ' '-' | tr -cd '[:alnum:]-')
        toc_html+="<li><a href='#${tid}'>$(html_encode "$tcat")</a></li>"
    done <<< "$toc_cats"

    # --- JSON data for export ---
    local json_findings="["
    local first_f=true
    for f in "${FINDINGS[@]}"; do
        local cat name risk desc details rec ref
        IFS='|' read -r cat name risk desc details rec ref <<< "$f"
        $first_f || json_findings+=","
        first_f=false
        # Basic JSON escaping
        local jcat jname jrisk jdesc jdet jrec jref
        jcat="${cat//\"/\\\"}"; jname="${name//\"/\\\"}"; jrisk="${risk//\"/\\\"}"
        jdesc="${desc//\"/\\\"}"; jdet="${details//\"/\\\"}"; jrec="${rec//\"/\\\"}"; jref="${ref//\"/\\\"}"
        json_findings+="{\"category\":\"${jcat}\",\"name\":\"${jname}\",\"risk\":\"${jrisk}\",\"description\":\"${jdesc}\",\"details\":\"${jdet}\",\"recommendation\":\"${jrec}\",\"reference\":\"${jref}\"}"
    done
    json_findings+="]"

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
.header-meta{font-size:14px;opacity:.9;margin-bottom:10px}
.header-meta div{margin:2px 0}
.header-btns{display:flex;gap:8px;margin-top:10px;flex-wrap:wrap}
.btn{border:none;padding:8px 18px;border-radius:6px;cursor:pointer;font-size:13px;font-weight:600}
.btn-green{background:#28a745;color:#fff}.btn-grey{background:#6c757d;color:#fff}
.score-circle{width:120px;height:120px;border-radius:50%;background:conic-gradient(${score_color} ${score}%,#ffffff33 0%);display:flex;align-items:center;justify-content:center;flex-shrink:0}
.score-inner{width:90px;height:90px;border-radius:50%;background:rgba(255,255,255,.95);display:flex;flex-direction:column;align-items:center;justify-content:center;color:var(--text)}
.score-value{font-size:32px;font-weight:700;color:${score_color}}
.score-label{font-size:11px;text-transform:uppercase;letter-spacing:1px}
.disclaimer{background:#fff3cd;border:1px solid #ffc107;border-radius:8px;padding:15px 20px;margin-bottom:20px;font-size:13px;color:#856404}
.disclaimer-warn{background:#fff0f0;border-color:#dc3545;color:#842029}.disclaimer-warn code{background:#f8d7da;padding:1px 5px;border-radius:3px;font-family:'SF Mono',Menlo,monospace}
.summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:24px}
.summary-card{background:var(--bg2);border-radius:10px;padding:20px;text-align:center;box-shadow:0 2px 8px rgba(0,0,0,.08);border-left:4px solid var(--border);cursor:pointer;transition:transform .15s,box-shadow .15s}
.summary-card:hover{transform:translateY(-2px);box-shadow:0 4px 14px rgba(0,0,0,.14)}
.summary-card.active-filter{outline:3px solid #1e3a5f;outline-offset:2px}
.summary-card.critical{border-left-color:var(--critical)}.summary-card.high{border-left-color:var(--high)}.summary-card.medium{border-left-color:var(--medium)}.summary-card.low{border-left-color:var(--low)}.summary-card.info{border-left-color:var(--info)}
.summary-card .count{font-size:36px;font-weight:700;margin-bottom:4px}
.summary-card.critical .count{color:var(--critical)}.summary-card.high .count{color:var(--high)}.summary-card.medium .count{color:var(--medium)}.summary-card.low .count{color:var(--low)}.summary-card.info .count{color:var(--info)}
.summary-card .label{font-size:13px;text-transform:uppercase;letter-spacing:1px;color:var(--text2)}
.ce-box{background:var(--bg2);border-radius:10px;padding:20px;margin-bottom:24px;box-shadow:0 2px 8px rgba(0,0,0,.08)}
.ce-box h3{font-size:18px;margin-bottom:16px;color:#1e3a5f;display:flex;justify-content:space-between;align-items:center}
.ce-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px}
.ce-item{border-radius:8px;padding:14px;border-left:4px solid var(--info)}
.ce-item.pass{border-left-color:#28a745;background:#f0fff4}.ce-item.fail{border-left-color:#dc3545;background:#fff5f5}.ce-item.review{border-left-color:#ffc107;background:#fffdf0}
.ce-item h4{font-size:13px;font-weight:600;margin-bottom:8px;display:flex;justify-content:space-between;align-items:center}
.ce-status{font-size:11px;padding:2px 8px;border-radius:4px;font-weight:700;white-space:nowrap}
.ce-status.pass{background:#28a745;color:#fff}.ce-status.fail{background:#dc3545;color:#fff}.ce-status.review{background:#ffc107;color:#212529}
.ce-notes{font-size:11px;color:var(--text2);line-height:1.6}
.toc-box{background:var(--bg2);border-radius:10px;padding:20px;margin-bottom:24px;box-shadow:0 2px 8px rgba(0,0,0,.08)}
.toc-box h3{font-size:16px;margin-bottom:12px;color:#1e3a5f}
.toc-box ul{list-style:none;columns:3;column-gap:20px}
.toc-box li{padding:3px 0}
.toc-box a{color:#2d5a87;text-decoration:none;font-size:13px}
.toc-box a:hover{text-decoration:underline}
.section{background:var(--bg2);border-radius:10px;margin-bottom:20px;box-shadow:0 2px 8px rgba(0,0,0,.08);overflow:hidden}
.section-header{background:#f1f3f4;padding:16px 20px;font-size:18px;font-weight:600;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;cursor:pointer;user-select:none}
.section-header:hover{background:#e8eaed}
.chevron{font-size:13px;transition:transform .2s;flex-shrink:0;margin-left:10px;color:var(--text2)}
.collapsed>.chevron,.collapsed .section-header .chevron{transform:rotate(-90deg)}
.collapsible-h3{cursor:pointer;user-select:none}
.collapsible-h3:hover{opacity:.85}
.section-content{padding:0}
.finding{padding:16px 20px;border-bottom:1px solid var(--border);display:grid;grid-template-columns:100px 1fr;gap:16px;align-items:start}
.finding:last-child{border-bottom:none}
.finding:hover{background:#f8f9fa}
.risk-badge{display:inline-block;padding:4px 12px;border-radius:20px;font-size:12px;font-weight:600;text-transform:uppercase;text-align:center;white-space:nowrap}
.risk-critical{background:var(--critical);color:#fff}.risk-high{background:var(--high);color:#fff}.risk-medium{background:var(--medium);color:#212529}.risk-low{background:var(--low);color:#fff}.risk-info{background:var(--info);color:#fff}
.finding-content h4{font-size:15px;font-weight:600;margin-bottom:6px}
.finding-content p{font-size:14px;color:var(--text2);margin-bottom:8px}
.finding-details{background:#f8f9fa;border-radius:6px;padding:10px 14px;font-family:'SF Mono',Menlo,monospace;font-size:12px;white-space:pre-wrap;word-break:break-all;margin-bottom:8px;max-height:180px;overflow-y:auto}
.recommendation{background:#e8f5e9;border-left:3px solid #28a745;padding:8px 12px;font-size:13px;margin-bottom:4px;border-radius:0 4px 4px 0}
.reference{font-size:12px;color:var(--text2);margin-top:4px}
.ns-box{background:var(--bg2);border-radius:10px;padding:20px;margin-bottom:24px;box-shadow:0 2px 8px rgba(0,0,0,.08)}
.ns-box h3{font-size:16px;margin-bottom:14px;color:#1e3a5f}
.ns-item{display:flex;gap:12px;align-items:flex-start;padding:10px 0;border-bottom:1px solid var(--border)}
.ns-item:last-child{border-bottom:none}
.ns-content{flex:1;font-size:13px}.ns-content strong{display:block;margin-bottom:3px}
.ns-rec{color:var(--text2);font-size:12px;margin-top:3px}.ns-none{color:#28a745;font-weight:600;font-size:14px}
.cis-box{background:var(--bg2);border-radius:10px;padding:20px;margin-bottom:24px;box-shadow:0 2px 8px rgba(0,0,0,.08)}
.cis-box h3{font-size:18px;margin-bottom:16px;color:#1e3a5f;display:flex;justify-content:space-between;align-items:center}
.cis-table{width:100%;border-collapse:collapse;font-size:13px}
.cis-table th{text-align:left;padding:8px 10px;background:#f1f3f4;border-bottom:2px solid var(--border);font-size:12px;text-transform:uppercase;letter-spacing:.5px;color:var(--text2)}
.cis-table td{padding:8px 10px;border-bottom:1px solid var(--border)}.cis-table tr:last-child td{border-bottom:none}
.cis-table tr:hover td{background:#f8f9fa}.cis-id{font-family:'SF Mono',Menlo,monospace;font-size:11px;color:var(--text2);white-space:nowrap}
.footer{text-align:center;padding:20px;color:var(--text2);font-size:13px}
@media(max-width:768px){.header{flex-direction:column;text-align:center}.finding{grid-template-columns:1fr}.toc-box ul{columns:1}}
@media print{body{background:#fff}.section{break-inside:avoid}.header{background:#1e3a5f!important;-webkit-print-color-adjust:exact}}
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
<div><strong>Platform:</strong> ${OS_NAME} ${OS_VERSION} (${OS_BUILD}) &mdash; ${CHIP}</div>
<div><strong>Privileges:</strong> ${admin_badge}</div>
</div>
<div class="header-btns">
<button class="btn btn-green" onclick="exportJson()">Export JSON</button>
<button class="btn btn-grey" onclick="window.print()">Print Report</button>
</div>
</div>
<div class="score-circle"><div class="score-inner"><div class="score-value">${score_grade}</div><div class="score-label">Score: ${score}</div></div></div>
</header>

<div class="disclaimer">
<strong>Disclaimer:</strong> This report is generated for authorised security compliance auditing purposes only.
Findings should be validated by qualified security personnel before taking remediation actions.
All checks are read-only &mdash; no system settings are modified.
</div>
$(if ! $IS_ROOT; then
echo '<div class="disclaimer disclaimer-warn"><strong>Warning: Audit not run as root.</strong> Several checks require elevated privileges to return accurate results. FileVault key escrow, TCC privacy permissions, secure boot configuration, and other system-level checks may be incomplete or missing. Re-run with <code>sudo bash audit.sh</code> for a complete report.</div>'
fi)

<div class="summary-grid">
<div class="summary-card critical" onclick="filterByRisk('critical')" title="Click to filter"><div class="count">${critical}</div><div class="label">Critical</div></div>
<div class="summary-card high" onclick="filterByRisk('high')" title="Click to filter"><div class="count">${high}</div><div class="label">High</div></div>
<div class="summary-card medium" onclick="filterByRisk('medium')" title="Click to filter"><div class="count">${medium}</div><div class="label">Medium</div></div>
<div class="summary-card low" onclick="filterByRisk('low')" title="Click to filter"><div class="count">${low}</div><div class="label">Low</div></div>
<div class="summary-card info" onclick="filterByRisk('info')" title="Click to filter"><div class="count">${info}</div><div class="label">Info</div></div>
</div>
<div id="filter-bar" style="display:none;margin-bottom:16px;padding:10px 16px;background:#e8f4fd;border-radius:8px;align-items:center;gap:12px;">
<span id="filter-label" style="font-weight:600;font-size:14px;"></span>
<button onclick="clearFilter()" style="padding:4px 12px;border:none;border-radius:4px;background:#6c757d;color:#fff;cursor:pointer;font-size:13px;">Show All</button>
</div>

<div class="ns-box">
<h3>Recommended Actions</h3>
${next_steps_html}
</div>

<div class="ce-box">
<h3 class="collapsible-h3" onclick="toggleSection(this)" style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0;padding-bottom:16px;border-bottom:1px solid var(--border);">Cyber Essentials Assessment <span style="font-size:14px;color:#28a745;margin-left:auto;padding-right:10px;">Readiness: ${ce_pct}%</span><span class="chevron">&#9660;</span></h3>
<div style="padding-top:16px;">
<div class="ce-grid">
<div class="ce-item ${ce_fw}">
<h4>Firewalls <span class="ce-status ${ce_fw}">$(echo "$ce_fw" | tr '[:lower:]' '[:upper:]')</span></h4>
<div class="ce-notes">${ce_fw_notes}</div>
</div>
<div class="ce-item ${ce_sc}">
<h4>Secure Configuration <span class="ce-status ${ce_sc}">$(echo "$ce_sc" | tr '[:lower:]' '[:upper:]')</span></h4>
<div class="ce-notes">${ce_sc_notes}</div>
</div>
<div class="ce-item ${ce_ac}">
<h4>User Access Control <span class="ce-status ${ce_ac}">$(echo "$ce_ac" | tr '[:lower:]' '[:upper:]')</span></h4>
<div class="ce-notes">${ce_ac_notes}</div>
</div>
<div class="ce-item ${ce_mp}">
<h4>Malware Protection <span class="ce-status ${ce_mp}">$(echo "$ce_mp" | tr '[:lower:]' '[:upper:]')</span></h4>
<div class="ce-notes">${ce_mp_notes}</div>
</div>
<div class="ce-item ${ce_pm}">
<h4>Patch Management <span class="ce-status ${ce_pm}">$(echo "$ce_pm" | tr '[:lower:]' '[:upper:]')</span></h4>
<div class="ce-notes">${ce_pm_notes}</div>
</div>
</div>
</div>
</div>

<div class="cis-box">
<h3 class="collapsible-h3" onclick="toggleSection(this)" style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0;padding-bottom:16px;border-bottom:1px solid var(--border);">CIS Benchmark Level 1 <span style="font-size:14px;color:#28a745;margin-left:auto;padding-right:10px;">Coverage: ${cis_pct}% (${cis_pass}/${cis_total})</span><span class="chevron">&#9660;</span></h3>
<div style="padding-top:16px;">
<table class="cis-table">
<thead><tr><th>Control</th><th>Description</th><th>Status</th></tr></thead>
<tbody>${cis_html}</tbody>
</table>
</div>
</div>

<div class="toc-box">
<h3>Table of Contents</h3>
<ul>${toc_html}</ul>
</div>

${findings_html}

<footer class="footer">
<p>Mac Security Audit Tool v${AUDIT_VERSION} | Generated: ${AUDIT_DATE}</p>
<p>Copyright &copy; 2026 Mac O Kay. Free to use and modify for personal, non-commercial use.</p>
<p><a href="https://github.com/macokay/Mac_Security_Audit" style="color:var(--text2);">github.com/macokay/Mac_Security_Audit</a></p>
</footer>
</div>

<script>
var AUDIT_DATA = {
  hostname: $(printf '"%s"' "${report_hostname}"),
  date: $(printf '"%s"' "${AUDIT_DATE}"),
  version: $(printf '"%s"' "${AUDIT_VERSION}"),
  os: $(printf '"%s %s (%s)"' "${OS_NAME}" "${OS_VERSION}" "${OS_BUILD}"),
  score: ${score},
  grade: $(printf '"%s"' "${score_grade}"),
  findings: ${json_findings}
};
function exportJson() {
  var blob = new Blob([JSON.stringify(AUDIT_DATA, null, 2)], {type: 'application/json'});
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'MacSecurityAudit_${report_hostname}_${AUDIT_DATE//[: ]/_}.json';
  a.click();
}
function toggleSection(header) {
  var body = header.nextElementSibling;
  if (!body) return;
  var hidden = body.style.display === 'none';
  body.style.display = hidden ? '' : 'none';
  var ch = header.querySelector('.chevron');
  if (ch) ch.style.transform = hidden ? '' : 'rotate(-90deg)';
}
var activeFilter = null;
function filterByRisk(risk) {
  if (activeFilter === risk) { clearFilter(); return; }
  activeFilter = risk;
  var findings = document.querySelectorAll('.finding');
  var sections = document.querySelectorAll('.section');
  findings.forEach(function(f) {
    f.style.display = f.getAttribute('data-risk') === risk ? '' : 'none';
  });
  sections.forEach(function(s) {
    var visible = s.querySelectorAll('.finding[data-risk="' + risk + '"]').length > 0;
    s.style.display = visible ? '' : 'none';
  });
  document.querySelectorAll('.summary-card').forEach(function(c) {
    c.classList.remove('active-filter');
  });
  var clicked = document.querySelector('.summary-card.' + risk);
  if (clicked) clicked.classList.add('active-filter');
  var bar = document.getElementById('filter-bar');
  bar.style.display = 'flex';
  document.getElementById('filter-label').textContent = 'Showing: ' + risk.toUpperCase() + ' findings only';
}
function clearFilter() {
  activeFilter = null;
  document.querySelectorAll('.finding').forEach(function(f) { f.style.display = ''; });
  document.querySelectorAll('.section').forEach(function(s) { s.style.display = ''; });
  document.querySelectorAll('.summary-card').forEach(function(c) { c.classList.remove('active-filter'); });
  document.getElementById('filter-bar').style.display = 'none';
}
</script>
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
    |          Copyright (C) 2026 Mac O Kay                            |
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
    test_edr_status
    test_secure_boot
    test_network_config
    test_disk_security
    test_privacy_settings
    test_find_my_mac
    test_time_machine
    test_software_inventory
    test_remote_access_tools
    test_browser_extensions
    test_audit_logging
    test_siem_forwarding
    test_tcc_permissions
    test_system_extensions
    test_authentication
    test_firewall_advanced
    test_network_security_advanced

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
        local firstline="${f%%$'\n'*}"
        local after_cat="${firstline#*|}"
        local after_name="${after_cat#*|}"
        local risk="${after_name%%|*}"
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
        if [[ -t 1 ]]; then
            printf "  Critical: $'\033[0;31m'%d$'\033[0m'\n" "$critical"
            printf "  High:     $'\033[0;33m'%d$'\033[0m'\n" "$high"
            printf "  Medium:   $'\033[0;33m'%d$'\033[0m'\n" "$medium"
            printf "  Low:      $'\033[0;36m'%d$'\033[0m'\n" "$low"
        else
            echo "  Critical: $critical"
            echo "  High:     $high"
            echo "  Medium:   $medium"
            echo "  Low:      $low"
        fi
        echo "==================================================================="
        echo ""

        # Try to open report
        if command -v open &>/dev/null; then
            open "$report_file" 2>/dev/null || true
        fi
    fi
}

main "$@"
