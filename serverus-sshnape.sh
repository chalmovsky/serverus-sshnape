#!/bin/bash

# =============================================================================
# Serverus SSHnape - secure a VPS with one command
# =============================================================================
# Usage: ./serverus-sshnape.sh <ip-or-domain>
#
# For Ubuntu servers. This script will:
#   1. Create an SSH key for this server
#   2. Copy it to the server (prompts for password once)
#   3. Remember the server's key in ~/.ssh/config, so `ssh root@<ip>` works
#   4. Harden SSH (disable password auth, root is key-only)
#   5. Setup UFW firewall, including the Docker bypass fix
#   6. Install and configure Fail2ban, with week-long bans for repeat offenders
#   7. Setup time sync
#   8. Add a swap file if there is no swap
#   9. Cap journal and Docker log sizes
#  10. Harden kernel network settings
#  11. Setup automatic security updates, rebooting at 04:00 UTC when needed
#  12. Configure security auditing
#  13. Lock root password
#  14. Send critical alerts to Telegram, if you say yes when asked
# =============================================================================

set -e

# -----------------------------------------------------------------------------
# Colors and formatting
# -----------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

# -----------------------------------------------------------------------------
# Helper functions
# -----------------------------------------------------------------------------
print_step() {
    echo -e "\n${BOLD}$1${NC}"
}

print_success() {
    echo -e "${GREEN}✔${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✖${NC} $1"
}

# -----------------------------------------------------------------------------
# Validate arguments
# -----------------------------------------------------------------------------
usage() {
    echo "Usage: ./serverus-sshnape.sh <ip-or-domain>"
    echo "Everything else is asked along the way."
}

SERVER=""

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            usage
            print_error "Unknown option: $1"
            exit 1
            ;;
        *)
            [ -n "$SERVER" ] && { usage; print_error "Unexpected argument: $1"; exit 1; }
            SERVER="$1"
            shift
            ;;
    esac
done

if [ -z "$SERVER" ]; then
    usage
    print_error "Missing server address"
    exit 1
fi

# The script always connects as root, so just the address
if ! [[ "$SERVER" =~ ^[A-Za-z0-9]([A-Za-z0-9._:-]*[A-Za-z0-9])?$ ]]; then
    usage
    print_error "Not an address: $SERVER (the IP or domain only, without root@)"
    exit 1
fi

# Create a safe name for the SSH key (replace dots and special chars)
KEY_NAME="vps_$(echo "$SERVER" | sed 's/[^a-zA-Z0-9]/_/g')"
KEY_PATH="$HOME/.ssh/${KEY_NAME}"

# Reuse one TCP connection for every check we make. Without this the script
# opens a fresh connection per step and trips the very `ufw limit 22/tcp` rule
# it just installed (6 connections in 30s = blocked), and then fails its own
# verification. %C is a short hash - a long ControlPath overflows the ~104 char
# unix socket limit on macOS.
SSH_MUX=(-o ControlMaster=auto -o "ControlPath=$HOME/.ssh/.serverus-sshnape-%C" -o ControlPersist=120)

close_mux() {
    ssh "${SSH_MUX[@]}" -O exit "root@$SERVER" 2>/dev/null || true
    rm -f "$HOME"/.ssh/.serverus-sshnape-* 2>/dev/null || true
}
trap close_mux EXIT

mkdir -p "$HOME/.ssh"
chmod 700 "$HOME/.ssh"

# Asked up front, so everything interactive happens before the long part.
TELEGRAM=""
TG_TOKEN=""
TG_CHAT=""
echo "Telegram alerts: logins from new IPs, changed SSH keys/users/cron, new open ports,"
echo "full disk, OOM kills, reboots. /status answers with a health check. Free."
read -rp "Set up Telegram alerts? (y/n) [n]: " want_telegram
if [ "$want_telegram" = "y" ] || [ "$want_telegram" = "Y" ]; then
    TELEGRAM=1
    echo "Message @BotFather in Telegram, send /newbot, paste the token here. One bot per server."
    # Hidden, so it stays out of the terminal scrollback
    read -rsp "Bot token: " TG_TOKEN
    echo ""

    if ! [[ "$TG_TOKEN" =~ ^[0-9]+:[A-Za-z0-9_-]+$ ]]; then
        print_error "Not a bot token (expected 123456789:ABC...)"
        exit 1
    fi

    BOT_NAME=$(curl -s --max-time 10 "https://api.telegram.org/bot$TG_TOKEN/getMe" | \
        grep -oE '"username":"[^"]+"' | head -1 | cut -d'"' -f4)
    if [ -z "$BOT_NAME" ]; then
        print_error "Telegram rejected the token"
        exit 1
    fi

    # The bot can't message you until you've messaged it - and that first
    # message is also how we learn your chat id.
    echo "Now send any message to @$BOT_NAME (waiting up to 2 minutes)"
    for _ in $(seq 1 60); do
        TG_CHAT=$(curl -s --max-time 10 "https://api.telegram.org/bot$TG_TOKEN/getUpdates" | \
            grep -oE '"chat":\{"id":-?[0-9]+' | tail -1 | grep -oE -- '-?[0-9]+$' || true)
        [ -n "$TG_CHAT" ] && break
        sleep 2
    done
    if [ -z "$TG_CHAT" ]; then
        print_error "No message arrived. Run again to retry."
        echo "  Another server using this bot grabs the message first: use one bot per server."
        echo "  This server already running it: ssh root@$SERVER systemctl stop serverus-sshnape-bot"
        exit 1
    fi
    # Reply right away: proves the bot can send, not just receive
    if ! curl -sf --max-time 10 -o /dev/null \
        --data-urlencode "chat_id=$TG_CHAT" \
        --data-urlencode "text=👋 Hello! Alerts will arrive here. Setting up the server now, you'll get a message when it's done." \
        "https://api.telegram.org/bot$TG_TOKEN/sendMessage"; then
        print_error "Could not send a message to this chat"
        exit 1
    fi
    print_success "Telegram: @$BOT_NAME said hello"
fi


# -----------------------------------------------------------------------------
# Generate SSH key
# -----------------------------------------------------------------------------
print_step "Key"

# Everything this machine remembers about the server: every known_hosts line
# for it (all key types, hashed entries, [ip]:port entries from a custom SSH
# port) and every key file for it, including .backup copies older versions of
# this script left behind.
forget_server() {
    local port
    ssh-keygen -R "$SERVER" >/dev/null 2>&1 || true
    for port in $(grep -oE "(^|,)\[$(echo "$SERVER" | sed 's/\./\\./g')\]:[0-9]+" "$HOME/.ssh/known_hosts" 2>/dev/null | sed 's/.*\]://' | sort -u); do
        ssh-keygen -R "[$SERVER]:$port" >/dev/null 2>&1 || true
    done
    rm -f "$KEY_PATH" "${KEY_PATH}.pub" "$KEY_PATH".backup.* "${KEY_PATH}".pub.backup.*
}

# One look at the server before any question is asked. It tells us whether the
# key we already have still gets in, and whether the server's host key changed.
# BatchMode stops at the host key check or at auth, so this never prompts.
PROBE_ARGS=(-o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10)
[ -f "$KEY_PATH" ] && PROBE_ARGS+=(-i "$KEY_PATH" -o IdentitiesOnly=yes)
PROBE_STATUS=0
PROBE_OUTPUT=$(ssh "${PROBE_ARGS[@]}" "root@$SERVER" true 2>&1) || PROBE_STATUS=$?

key_choice=""
if [ -f "$KEY_PATH" ]; then
    echo "Key exists at $KEY_PATH."
    echo "  a) Reuse it"
    echo "  b) Start fresh (reinstalled server): delete every key for $SERVER"
    echo "     ($KEY_PATH, .pub, old .backup copies), remove every $SERVER line"
    echo "     from ~/.ssh/known_hosts, make a new key"
    while [ "$key_choice" != "a" ] && [ "$key_choice" != "b" ]; do
        read -rp "a or b: " key_choice
        key_choice=$(echo "$key_choice" | tr 'AB' 'ab')
    done
    # The key still gets in, so this server was not reinstalled. Password login
    # is off there: delete the key and the new one can't be installed either.
    if [ "$key_choice" = "b" ] && [ "$PROBE_STATUS" -eq 0 ]; then
        print_warning "This key still logs in to $SERVER, so the server was not reinstalled."
        echo "  Password login is off on a hardened server. Without this key, and with no"
        echo "  other key of yours on the server, there is no way back in."
        read -rp "Delete it anyway? (y/n): " delete_anyway
        if [ "$delete_anyway" != "y" ] && [ "$delete_anyway" != "Y" ]; then
            key_choice="a"
        fi
    fi
    if [ "$key_choice" = "b" ]; then
        forget_server
        ssh-keygen -t ed25519 -f "$KEY_PATH" -N "" -C "serverus-sshnape-$SERVER" -q
        print_success "New key: $KEY_PATH (old keys and known_hosts lines removed)"
    else
        print_success "Key: $KEY_PATH"
    fi
else
    ssh-keygen -t ed25519 -f "$KEY_PATH" -N "" -C "serverus-sshnape-$SERVER" -q
    print_success "Key: $KEY_PATH"
fi

# -----------------------------------------------------------------------------
# Check the server's host key against known_hosts
# -----------------------------------------------------------------------------
# A reinstalled VPS comes back with a new host key, and ssh refuses to connect
# until the old one is removed. Catch that before asking for the password
# instead of failing on it. Starting fresh above already removed it.
if [ "$key_choice" != "b" ] && echo "$PROBE_OUTPUT" | grep -q "REMOTE HOST IDENTIFICATION HAS CHANGED"; then
    print_warning "$SERVER has a different host key than last time."
    echo "  Expected after a reinstall. If you did not reinstall it, someone may be"
    echo "  intercepting the connection - stop here."
    read -rp "Reinstalled it? Forget the old host key? (y/n): " forget_hostkey
    if [ "$forget_hostkey" != "y" ] && [ "$forget_hostkey" != "Y" ]; then
        print_error "Stopped. Nothing was changed."
        exit 1
    fi
    ssh-keygen -R "$SERVER" >/dev/null 2>&1
    print_success "Old host key removed from ~/.ssh/known_hosts"
fi

# -----------------------------------------------------------------------------
# Copy SSH key to server
# -----------------------------------------------------------------------------
echo "Root password (asked once):"

set +e
COPY_OUTPUT=$(ssh-copy-id -i "$KEY_PATH" -o StrictHostKeyChecking=accept-new "root@$SERVER" 2>&1)
COPY_STATUS=$?
set -e

if [ $COPY_STATUS -ne 0 ]; then
    print_error "Could not copy the key to root@$SERVER"
    echo "$COPY_OUTPUT" | grep -vE '^\s*$|^/usr/bin/ssh-copy-id|^INFO:' | sed 's/^/  /'
    echo "  Check the address, the password, and that root may log in with a password."
    exit 1
fi

# -----------------------------------------------------------------------------
# Test SSH key authentication
# -----------------------------------------------------------------------------
if ! ssh -i "$KEY_PATH" "${SSH_MUX[@]}" -o PasswordAuthentication=no -o ConnectTimeout=10 "root@$SERVER" "echo ok" &>/dev/null; then
    print_error "Key login failed. Nothing was changed; password login still works."
    echo "  Check ~/.ssh/authorized_keys on the server."
    exit 1
fi

print_success "Key login works"

# -----------------------------------------------------------------------------
# Update local SSH config
# -----------------------------------------------------------------------------

SSH_CONFIG="$HOME/.ssh/config"
BEGIN_MARKER="# BEGIN serverus-sshnape: $SERVER"
END_MARKER="# END serverus-sshnape: $SERVER"

touch "$SSH_CONFIG"

# Drop any block we wrote previously so re-runs update the key instead of
# stacking duplicate entries.
if grep -qxF "$BEGIN_MARKER" "$SSH_CONFIG"; then
    sed -i.bak "/^${BEGIN_MARKER}$/,/^${END_MARKER}$/d" "$SSH_CONFIG"
    rm -f "${SSH_CONFIG}.bak"
elif grep -qxF "Host $SERVER" "$SSH_CONFIG"; then
    # An unmanaged entry from an older run (or hand-written) - leave it alone.
    # ssh takes the first value it sees for each option, so that block's
    # IdentityFile would win over ours anyway.
    SKIP_SSH_CONFIG=1
    if awk -v host="Host $SERVER" -v key="$KEY_PATH" '
        $0 == host { inblock = 1; next }
        /^[[:space:]]*(Host|Match)[[:space:]]/ { inblock = 0 }
        inblock && $1 == "IdentityFile" && $2 == key { found = 1 }
        END { exit !found }' "$SSH_CONFIG"; then
        print_success "~/.ssh/config: your 'Host $SERVER' entry already uses this key"
    else
        print_warning "$SSH_CONFIG already has 'Host $SERVER' with a different key."
        echo "  Change its IdentityFile to $KEY_PATH, or delete that entry and re-run."
    fi
fi

if [ -z "${SKIP_SSH_CONFIG:-}" ]; then

    # Add newline if file exists and doesn't end with one
    if [ -s "$SSH_CONFIG" ]; then
        tail -c1 "$SSH_CONFIG" | read -r _ || echo "" >> "$SSH_CONFIG"
        echo "" >> "$SSH_CONFIG"
    fi

    # Match on host *and* user rather than a plain Host block: you connect the
    # normal way, spelling out who you are - ssh root@$SERVER - instead of
    # relying on a User line here.
    cat >> "$SSH_CONFIG" << EOF
$BEGIN_MARKER
# Added $(date +%Y-%m-%d) - connect with: ssh root@$SERVER
Match host $SERVER user root
    IdentityFile $KEY_PATH
    IdentitiesOnly yes
$END_MARKER
EOF

    chmod 600 "$SSH_CONFIG"
    print_success "~/.ssh/config: ssh root@$SERVER uses this key"
fi

# -----------------------------------------------------------------------------
# Run hardening on remote server
# -----------------------------------------------------------------------------
print_step "Server"

# The Telegram token travels on stdin with the script, not on the command
# line, where `ps` on the server would show it.
REMOTE_STATUS=0
{
    printf 'TG_TOKEN=%q\nTG_CHAT=%q\n' "$TG_TOKEN" "$TG_CHAT"
    cat << 'REMOTE_SCRIPT'
#!/bin/bash

set -eE

# Colors for remote output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'
ok()   { echo -e "${GREEN}✔${NC} $1"; }
warn() { echo -e "${YELLOW}⚠${NC} $1"; }
fail() { echo -e "${RED}✖${NC} $1"; }

# Most steps run with their output hidden - never stop without saying where
trap 'fail "Stopped at: $BASH_COMMAND"' ERR

# Ubuntu only
PRETTY_NAME="an unknown system"
[ -f /etc/os-release ] && . /etc/os-release
if [ "${ID:-}" != "ubuntu" ]; then
    fail "This is $PRETTY_NAME. Only Ubuntu is supported. Nothing was changed."
    exit 1
fi

# On re-runs, pause the alert watcher so it doesn't report this script's own
# changes. Restarted even if we bail out halfway.
if systemctl cat serverus-sshnape-watch.timer > /dev/null 2>&1; then
    systemctl stop serverus-sshnape-watch.timer > /dev/null 2>&1 || true
    trap 'systemctl start serverus-sshnape-watch.timer > /dev/null 2>&1 || true' EXIT
fi

ok "OS: $PRETTY_NAME"

# -------------------------------------------------------------------------
# Update system
# -------------------------------------------------------------------------
# stdin is this script. Anything that reads it would eat the steps that
# follow, so package managers get /dev/null.
# A fresh VPS is often still running its own first-boot apt job,
# which holds the lock for a minute or two
APT_UPDATED=""
for _ in 1 2 3 4 5 6; do
    if apt-get update < /dev/null > /dev/null 2>&1; then
        APT_UPDATED=1
        break
    fi
    sleep 10
done
[ -n "$APT_UPDATED" ] || warn "apt-get update failed, using the package lists already here"

# -------------------------------------------------------------------------
# Install required packages
# -------------------------------------------------------------------------
INSTALL_LOG=$(mktemp)

# python3-systemd: needed by fail2ban's systemd backend
# Lock::Timeout: wait for another apt instead of failing on its lock.
# force-confold: keep config files as they are, without asking
if ! DEBIAN_FRONTEND=noninteractive apt-get install -y \
    -o DPkg::Lock::Timeout=300 -o Dpkg::Options::=--force-confold \
    ufw \
    fail2ban \
    python3-systemd \
    curl \
    unattended-upgrades \
    apt-listchanges \
    auditd \
    audispd-plugins \
    acct \
    chrony \
    < /dev/null > "$INSTALL_LOG" 2>&1; then
    fail "Package install failed:"
    tail -20 "$INSTALL_LOG" | sed 's/^/  /'
    exit 1
fi

rm -f "$INSTALL_LOG"

ok "Packages installed"

# -------------------------------------------------------------------------
# Configure SSH
# -------------------------------------------------------------------------

SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_DROPIN_DIR="/etc/ssh/sshd_config.d"
SSHD_DROPIN="$SSHD_DROPIN_DIR/00-hardening.conf"

# The config as it was before the first run is kept for good. For undoing
# this run there's a throwaway copy - not in /etc/ssh, re-runs would pile up.
if ! ls "${SSHD_CONFIG}".backup.* > /dev/null 2>&1; then
    cp -p "$SSHD_CONFIG" "${SSHD_CONFIG}.backup.$(date +%s)"
fi
SSHD_BACKUP=$(mktemp)
cp "$SSHD_CONFIG" "$SSHD_BACKUP"

restore_sshd_config() {
    cp "$SSHD_BACKUP" "$SSHD_CONFIG"
    rm -f "$SSHD_DROPIN"
}

# Function to set SSH config option
set_ssh_option() {
    local key="$1"
    local value="$2"
    if grep -qE "^${key}\b" "$SSHD_CONFIG"; then
        sed -i -E "s/^${key}\b.*/${key} ${value}/" "$SSHD_CONFIG"
    elif grep -qE "^#${key}\b" "$SSHD_CONFIG"; then
        sed -i -E "s/^#${key}\b.*/${key} ${value}/" "$SSHD_CONFIG"
    else
        echo "${key} ${value}" >> "$SSHD_CONFIG"
    fi
}

# Apply SSH hardening (ChallengeResponse is the pre-8.7 name for KbdInteractive)
set_ssh_option "PermitRootLogin" "prohibit-password"
set_ssh_option "PasswordAuthentication" "no"
set_ssh_option "PermitEmptyPasswords" "no"
set_ssh_option "ChallengeResponseAuthentication" "no"
set_ssh_option "KbdInteractiveAuthentication" "no"
set_ssh_option "UsePAM" "yes"
set_ssh_option "X11Forwarding" "no"
set_ssh_option "MaxAuthTries" "3"
set_ssh_option "ClientAliveInterval" "300"
set_ssh_option "ClientAliveCountMax" "2"
set_ssh_option "LoginGraceTime" "60"

# Cloud images ship drop-ins like sshd_config.d/50-cloud-init.conf that set
# "PasswordAuthentication yes" and silently override the main config (sshd uses
# the first value it sees). A 00- prefixed drop-in sorts first and wins.
if [ -d "$SSHD_DROPIN_DIR" ] && grep -qE '^\s*Include\s+/etc/ssh/sshd_config\.d/' "$SSHD_CONFIG"; then
    cat > "$SSHD_DROPIN" << 'EOF'
# Managed by serverus-sshnape
PermitRootLogin prohibit-password
PasswordAuthentication no
PermitEmptyPasswords no
KbdInteractiveAuthentication no
X11Forwarding no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 60
EOF
fi

# Validate syntax before restarting
if ! sshd -t; then
    fail "sshd config invalid - restored the original"
    restore_sshd_config
    exit 1
fi

# Verify the effective config - catches any drop-in still overriding us
SSHD_EFFECTIVE=$(sshd -T 2>/dev/null || true)
if ! echo "$SSHD_EFFECTIVE" | grep -qiE '^passwordauthentication\s+no'; then
    fail "Password auth still on in the effective config - restored the original. Check /etc/ssh/sshd_config.d/"
    restore_sshd_config
    exit 1
fi
if ! echo "$SSHD_EFFECTIVE" | grep -qiE '^permitrootlogin\s+(prohibit-password|without-password)'; then
    fail "PermitRootLogin not key-only in the effective config - restored the original"
    restore_sshd_config
    exit 1
fi

systemctl restart ssh
rm -f "$SSHD_BACKUP"
ok "SSH: key only, no passwords"

# -------------------------------------------------------------------------
# Configure Firewall
# -------------------------------------------------------------------------

# First run: start from a clean slate. Re-runs skip the reset - it
# would throw away rules you've added since, and switches the
# firewall off until it's enabled again a few lines down.
FW_KEPT=""
if ufw status 2>/dev/null | grep -qE '^22/tcp +LIMIT'; then
    FW_KEPT=", your other rules kept"
else
    ufw --force reset > /dev/null 2>&1
fi

# Set defaults
ufw default deny incoming > /dev/null 2>&1
ufw default allow outgoing > /dev/null 2>&1

# Allow SSH with rate limiting (MUST be before enabling!)
# 'limit' blocks IPs making 6+ connections in 30 seconds
ufw limit 22/tcp > /dev/null 2>&1

# Allow common web ports (comment out if not needed)
ufw allow 80/tcp > /dev/null 2>&1
ufw allow 443/tcp > /dev/null 2>&1

# Enable firewall
ufw --force enable > /dev/null 2>&1

ok "Firewall: 22 (rate-limited), 80, 443 open${FW_KEPT:-, everything else closed}"

# -------------------------------------------------------------------------
# Stop Docker from bypassing the firewall
# -------------------------------------------------------------------------
# Docker writes its own iptables rules into the DOCKER chain, which is
# evaluated BEFORE ufw's chains. The result: `docker run -p 6791:6791` is
# reachable from the internet while `ufw status` still swears the port is
# closed. The DOCKER-USER chain is the one hook Docker leaves for us - it is
# consulted before any of Docker's own rules, and Docker never rewrites it.
#
# This must run AFTER the firewall step: `ufw --force reset` restores a stock
# after.rules.
# ufw drops forwarded packets by default, which breaks container
# networking outright. Hand filtering to DOCKER-USER instead.
if grep -qE '^DEFAULT_FORWARD_POLICY=' /etc/default/ufw; then
    sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
else
    echo 'DEFAULT_FORWARD_POLICY="ACCEPT"' >> /etc/default/ufw
fi

# Idempotent: strip any block we added before, then append a fresh one
if grep -q '^# BEGIN UFW AND DOCKER$' /etc/ufw/after.rules; then
    sed -i '/^# BEGIN UFW AND DOCKER$/,/^# END UFW AND DOCKER$/d' /etc/ufw/after.rules
fi

cat >> /etc/ufw/after.rules << 'EOF'
# BEGIN UFW AND DOCKER
*filter
:ufw-user-forward - [0:0]
:ufw-docker-logging-deny - [0:0]
:DOCKER-USER - [0:0]
-A DOCKER-USER -j ufw-user-forward

# Established/related traffic and container-to-container stay untouched
-A DOCKER-USER -j RETURN -s 10.0.0.0/8
-A DOCKER-USER -j RETURN -s 172.16.0.0/12
-A DOCKER-USER -j RETURN -s 192.168.0.0/16

# Container DNS replies
-A DOCKER-USER -p udp -m udp --sport 53 --dport 1024:65535 -j RETURN

# Anything from outside aimed at a container gets dropped unless a ufw rule
# allowed it. Published ports are no longer world-open by default.
-A DOCKER-USER -j ufw-docker-logging-deny -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -d 192.168.0.0/16
-A DOCKER-USER -j ufw-docker-logging-deny -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -d 10.0.0.0/8
-A DOCKER-USER -j ufw-docker-logging-deny -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -d 172.16.0.0/12
-A DOCKER-USER -j ufw-docker-logging-deny -p udp -m udp --dport 0:32767 -d 192.168.0.0/16
-A DOCKER-USER -j ufw-docker-logging-deny -p udp -m udp --dport 0:32767 -d 10.0.0.0/8
-A DOCKER-USER -j ufw-docker-logging-deny -p udp -m udp --dport 0:32767 -d 172.16.0.0/12

-A DOCKER-USER -j RETURN

-A ufw-docker-logging-deny -m limit --limit 3/min --limit-burst 10 -j LOG --log-prefix "[UFW DOCKER BLOCK] "
-A ufw-docker-logging-deny -j DROP

COMMIT
# END UFW AND DOCKER
EOF

# DOCKER-USER consults ufw's *route* rules, not the input rules above.
# Without these, a containerised reverse proxy (kamal-proxy, Traefik,
# Caddy in Docker) publishing 80/443 is unreachable from outside.
ufw route allow proto tcp from any to any port 80 > /dev/null 2>&1
ufw route allow proto tcp from any to any port 443 > /dev/null 2>&1

ufw reload > /dev/null 2>&1 || true
ok "Docker: containers reachable from outside on 80 and 443 only"

# -------------------------------------------------------------------------
# Configure Fail2ban
# -------------------------------------------------------------------------

# systemd backend reads the journal directly - no logpath needed
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
# Ban for 1 hour
bantime = 3600
# Find failures within 10 minutes
findtime = 600
# Ban after 5 failures
maxretry = 5
# Read auth events from the systemd journal
backend = systemd

[sshd]
enabled = true
port = ssh
filter = sshd
maxretry = 3
bantime = 3600

# Repeat offenders: banned 3 times within a day = banned for a week, on all
# ports. Reads fail2ban's own log, not the journal.
[recidive]
enabled = true
backend = auto
logpath = /var/log/fail2ban.log
findtime = 86400
maxretry = 3
bantime = 604800
EOF

# recidive needs fail2ban logging to a file, and fail2ban refuses to start at
# all if a jail's logpath is missing.
cat > /etc/fail2ban/fail2ban.local << 'EOF'
[Definition]
logtarget = /var/log/fail2ban.log
EOF
touch /var/log/fail2ban.log

systemctl enable fail2ban > /dev/null 2>&1
if ! systemctl restart fail2ban > /dev/null 2>&1; then
    warn "Fail2ban not running: journalctl -u fail2ban"
else
    ok "Fail2ban: 3 failures = 1 hour ban, 3 bans = 1 week"
fi

# -------------------------------------------------------------------------
# Configure time sync
# -------------------------------------------------------------------------

# A drifting clock breaks TLS, TOTP and log correlation. chrony replaces
# systemd-timesyncd.
timedatectl set-timezone UTC > /dev/null 2>&1 || true
systemctl enable --now chrony > /dev/null 2>&1 || true

if systemctl is-active --quiet chrony; then
    ok "Clock: chrony, UTC"
else
    warn "chrony not running: systemctl status chrony"
fi

# -------------------------------------------------------------------------
# Configure swap
# -------------------------------------------------------------------------

# Without swap, running out of RAM means the kernel kills a process - usually
# the biggest one, which is usually your database. Swap turns that crash into
# a slowdown. Existing swap is left alone.
if [ -n "$(swapon --show --noheadings 2>/dev/null)" ]; then
    ok "Swap: already present"
else
    RAM_MB=$(awk '/^MemTotal:/ {print int($2 / 1024)}' /proc/meminfo)
    # Match RAM, clamped to 1-4 GB. It's a safety net, not extra memory.
    SWAP_MB=$(( RAM_MB < 1024 ? 1024 : (RAM_MB > 4096 ? 4096 : RAM_MB) ))
    FREE_MB=$(df -Pm / | awk 'NR == 2 {print $4}')

    if [ "$FREE_MB" -lt $(( SWAP_MB + 2048 )) ]; then
        warn "Swap: skipped, only ${FREE_MB} MB free on /"
    else
        rm -f /swapfile
        touch /swapfile
        chmod 600 /swapfile
        # btrfs refuses copy-on-write swap files; a no-op error elsewhere
        chattr +C /swapfile 2>/dev/null || true

        if { fallocate -l "${SWAP_MB}M" /swapfile 2>/dev/null || \
             dd if=/dev/zero of=/swapfile bs=1M count="$SWAP_MB" status=none; } && \
           mkswap /swapfile > /dev/null 2>&1 && \
           swapon /swapfile 2>/dev/null; then
            grep -qE '^/swapfile\s' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
            # Only reach for swap under real memory pressure
            echo 'vm.swappiness = 10' > /etc/sysctl.d/99-swap.conf
            sysctl -q -p /etc/sysctl.d/99-swap.conf || true
            ok "Swap: ${SWAP_MB} MB at /swapfile"
        else
            # Container-based VPSes (OpenVZ, LXC) don't allow swapon
            rm -f /swapfile
            warn "Swap: not allowed on this VPS, skipped"
        fi
    fi
fi

# -------------------------------------------------------------------------
# Cap log sizes
# -------------------------------------------------------------------------

# A full disk takes the app down with it - SQLite can't write, deploys fail.
# Unbounded logs are the usual way a box you don't babysit gets there.
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/00-serverus-sshnape.conf << 'EOF'
[Journal]
SystemMaxUse=500M
EOF
systemctl restart systemd-journald > /dev/null 2>&1 || true

# Docker keeps container logs forever by default. Written before Docker is
# installed so it applies from the first container. Merged into any existing
# daemon.json rather than replacing it; a log setup that's already there wins.
# Docker isn't restarted - that would restart every container. New containers
# (i.e. the next deploy) pick it up.
mkdir -p /etc/docker
DOCKER_LOGS=$(python3 - << 'PYEOF'
import json, os
path = "/etc/docker/daemon.json"
cfg = {}
if os.path.exists(path):
    try:
        with open(path) as f:
            cfg = json.load(f)
    except ValueError:
        cfg = None
if not isinstance(cfg, dict):
    print("invalid")
    raise SystemExit
driver = cfg.get("log-driver", "json-file")
if driver != "json-file" or "max-size" in cfg.get("log-opts", {}):
    print("kept")
    raise SystemExit
cfg["log-driver"] = "json-file"
cfg.setdefault("log-opts", {}).update({"max-size": "10m", "max-file": "3"})
with open(path, "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
print("set")
PYEOF
) || DOCKER_LOGS=invalid

case "$DOCKER_LOGS" in
    set)     ok "Logs: journal 500 MB, Docker 10 MB x 3 per container" ;;
    kept)    ok "Logs: journal 500 MB, Docker settings kept as they were" ;;
    *)       warn "Logs: journal 500 MB; Docker not capped, /etc/docker/daemon.json is not valid JSON" ;;
esac

# -------------------------------------------------------------------------
# Kernel hardening
# -------------------------------------------------------------------------

# Reverse-path filtering is left at the distro default: strict mode drops
# legitimate traffic on hosts with a private network or asymmetric routing.
cat > /etc/sysctl.d/99-serverus-sshnape.conf << 'EOF'
# Managed by serverus-sshnape

# SYN flood protection
net.ipv4.tcp_syncookies = 1

# Don't let other hosts rewrite our routes
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Ignore source-routed packets
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Ignore broadcast pings and bogus ICMP errors
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Keep kernel addresses and logs away from unprivileged users
kernel.kptr_restrict = 1
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
fs.suid_dumpable = 0
EOF

# -e: skip keys this kernel doesn't have instead of failing
sysctl -q -e -p /etc/sysctl.d/99-serverus-sshnape.conf > /dev/null 2>&1 || true
ok "Kernel: SYN cookies, no redirects, no source routing"

# -------------------------------------------------------------------------
# Configure Automatic Updates
# -------------------------------------------------------------------------

# Ubuntu's own 50unattended-upgrades knows which updates are security
# updates, so it stays as it is and our settings go in a file next to it.

# Kernel fixes do nothing until a reboot. Reboot only when an update
# actually needs it, at a quiet hour (server time is UTC).
cat > /etc/apt/apt.conf.d/52unattended-upgrades-serverus-sshnape << 'EOF'
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";
EOF

cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
ok "Updates: automatic, reboot at 04:00 UTC when needed"

# -------------------------------------------------------------------------
# Configure Security Auditing
# -------------------------------------------------------------------------

# Configure auditd rules for intrusion detection
cat > /etc/audit/rules.d/hardening.rules << 'EOF'
# Delete all existing rules
-D

# Set buffer size
-b 8192

# Failure mode (1 = printk, 2 = panic)
-f 1

# ============================================================
# AUTHENTICATION & LOGIN MONITORING
# ============================================================

# Monitor authentication files
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity

# Monitor sudoers
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# ============================================================
# SSH MONITORING
# ============================================================

# Monitor SSH configuration. One rule for the whole directory: with a second
# one for sshd_config itself, changes to that file carry the second rule's
# key, and whoever reads only ssh_config misses them.
-w /etc/ssh/ -p wa -k ssh_config

# ============================================================
# USER & SESSION MONITORING
# ============================================================

# Monitor user/group management commands
-w /usr/sbin/useradd -p x -k user_modification
-w /usr/sbin/usermod -p x -k user_modification
-w /usr/sbin/userdel -p x -k user_modification
-w /usr/sbin/groupadd -p x -k group_modification
-w /usr/sbin/groupmod -p x -k group_modification
-w /usr/sbin/groupdel -p x -k group_modification

# Monitor PAM configuration
-w /etc/pam.d/ -p wa -k pam

# ============================================================
# PRIVILEGED COMMAND EXECUTION
# ============================================================

# Monitor sudo usage
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=4294967295 -k privileged_command
-a always,exit -F arch=b32 -S execve -F euid=0 -F auid>=1000 -F auid!=4294967295 -k privileged_command

# ============================================================
# SYSTEM CHANGES
# ============================================================

# Monitor cron
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

# Monitor systemd services
-w /etc/systemd/ -p wa -k systemd
-w /lib/systemd/ -p wa -k systemd

# Monitor network configuration
-w /etc/hosts -p wa -k network_config
EOF

# Watches on missing paths abort the whole rule set - only add ones that exist
for LOGIN_LOG in /var/log/lastlog /var/log/faillog /var/log/tallylog; do
    [ -e "$LOGIN_LOG" ] && echo "-w $LOGIN_LOG -p wa -k logins" >> /etc/audit/rules.d/hardening.rules
done
[ -e /etc/security/opasswd ] && echo "-w /etc/security/opasswd -p wa -k identity" >> /etc/audit/rules.d/hardening.rules
[ -d /etc/network ] && echo "-w /etc/network/ -p wa -k network_config" >> /etc/audit/rules.d/hardening.rules

# SSH keys of every account that can log in - cloud images ship a default
# user with passwordless sudo next to root. The whole ~/.ssh is watched rather
# than authorized_keys: sshd reads authorized_keys2 as well, and a watch can't
# be set on a file that isn't there yet. sort -u: a duplicate rule is an error.
awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ {print $6}' /etc/passwd | sort -u | \
    while read -r HOME_DIR; do
        if [ -d "$HOME_DIR/.ssh" ]; then
            echo "-w $HOME_DIR/.ssh/ -p wa -k authorized_keys"
        fi
    done >> /etc/audit/rules.d/hardening.rules

cat >> /etc/audit/rules.d/hardening.rules << 'EOF'

# Make the configuration immutable (requires reboot to change)
-e 2
EOF

# auditd.service ships with ProtectHome=true, and augenrules loads the rules
# from inside that sandbox. /root and /home are hidden there, so the ~/.ssh
# watches fail with "No such file or directory" - and auditctl stops at the
# first failure, silently dropping every rule after it. Read-only is enough
# for the paths to resolve.
mkdir -p /etc/systemd/system/auditd.service.d
cat > /etc/systemd/system/auditd.service.d/serverus-sshnape.conf << 'EOF'
# Managed by serverus-sshnape: let augenrules see ~/.ssh of root and users
[Service]
ProtectHome=read-only
EOF
systemctl daemon-reload

# On re-runs the rules are locked (-e 2) until the next reboot
AUDIT_LOCKED=""
auditctl -s 2>/dev/null | grep -q '^enabled 2' && AUDIT_LOCKED=1

systemctl enable auditd > /dev/null 2>&1 || true
service auditd restart > /dev/null 2>&1 || systemctl restart auditd > /dev/null 2>&1 || true

# A rule that fails to load takes all the rules after it down. The lock is
# the last line of the file: if it's on, everything before it made it in.
sleep 1
AUDIT_STATE=ok
if ! auditctl -s 2>/dev/null | grep -q '^enabled 2'; then
    AUDIT_STATE=broken
elif [ -n "$AUDIT_LOCKED" ]; then
    # Locked before we came: is every watch in the file among the loaded ones?
    AUDIT_LOADED=$(auditctl -l 2>/dev/null)
    AUDIT_MISSING=$(sed -nE 's|^-w ([^ ]*[^ /])/? .*|\1|p' /etc/audit/rules.d/hardening.rules | \
        while read -r WATCHED; do
            echo "$AUDIT_LOADED" | grep -qF -- "-w $WATCHED -p " || echo "$WATCHED"
        done)
    [ -z "$AUDIT_MISSING" ] || AUDIT_STATE=reboot
fi

# Enable process accounting
systemctl enable --now acct > /dev/null 2>&1 || true

case $AUDIT_STATE in
    ok)     ok "Audit: SSH keys, users, sudoers, cron, systemd, PAM" ;;
    reboot) warn "Audit: new rules are saved, they load at the next reboot (locked until then)" ;;
    *)      warn "Audit: not all rules loaded, so change alerts may not fire. Check: augenrules --load" ;;
esac

# -------------------------------------------------------------------------
# Create security check script
# -------------------------------------------------------------------------

# What changed, who did it, with what. Used by security-check and by the
# Telegram watcher.
mkdir -p /usr/local/lib/serverus-sshnape
cat > /usr/local/lib/serverus-sshnape/audit-changes << 'EOF'
#!/bin/bash
# Usage: audit-changes <audit key> <from> <to>    (times in epoch seconds)
# Prints one line per change auditd recorded under that key in that window:
#   file <tab> who <tab> program
# who is the account that logged in (auid), however it became root later;
# 4294967295 means nobody logged in, e.g. a service. "-" stands for unknown.
# Skipped: rule loads by auditctl, and the temp files editors, sed -i and
# passwd leave behind (authorized_keys~, .swp, sedAbC123, shadow+). Relative
# paths are made absolute with the CWD record - vim saves by a relative name.
# --input-logs: without it ausearch reads stdin whenever stdin isn't a tty.
KEY=$1
FROM=$2
TO=$3
# ~/.ssh is watched as a whole; only the files sshd reads keys from count
ONLY=""
[ "$KEY" = authorized_keys ] && ONLY='/authorized_keys2?$'

ausearch --input-logs -k "$KEY" \
        -ts "$(date -d "@$FROM" '+%x')" "$(date -d "@$FROM" '+%T')" 2>/dev/null | \
    awk -v from="$FROM" -v to="$TO" -v only="$ONLY" '
        function field(k,   v) {
            if (!match($0, " " k "=(\"[^\"]*\"|[^ ]+)")) return ""
            v = substr($0, RSTART + length(k) + 2, RLENGTH - length(k) - 2)
            gsub(/"/, "", v)
            return v
        }
        match($0, /msg=audit\([0-9.]+:[0-9]+\)/) {
            id = substr($0, RSTART + 10, RLENGTH - 11)
            t = substr(id, 1, index(id, ":") - 1) + 0
            if (t < from || t >= to) next
            if ($0 ~ /^type=SYSCALL/) {
                if (field("exe") ~ /\/auditctl$/) next
                sys[id] = 1; who[id] = field("auid"); exe[id] = field("exe")
            } else if ($0 ~ /^type=CWD/) {
                cwd[id] = field("cwd")
            } else if ($0 ~ /^type=PATH/ && $0 !~ /nametype=PARENT/) {
                n = field("name")
                if (n != "" && n != "(null)") names[id] = names[id] SUBSEP n
            }
        }
        END {
            for (id in sys) {
                c = split(substr(names[id], 2), list, SUBSEP)
                # No file name on record, e.g. a chmod through an open file
                if (c == 0) {
                    if (only == "") print "-\t" who[id] "\t" exe[id]
                    continue
                }
                for (i = 1; i <= c; i++) {
                    f = list[i]
                    if (f !~ /^\//) f = cwd[id] "/" f
                    if (f ~ /(~|\+|-|\.sw[a-p]|\/4913|\.lock)$/) continue
                    if (f ~ /\/sed[A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9]$/) continue
                    if (only != "" && f !~ only) continue
                    print f "\t" who[id] "\t" exe[id]
                }
            }
        }' | \
    while IFS=$'\t' read -r FILE AUID EXE; do
        if [ -z "$AUID" ] || [ "$AUID" = 4294967295 ]; then
            WHO="a system service (nobody logged in)"
        else
            WHO=$(getent passwd "$AUID" | cut -d: -f1)
            WHO=${WHO:-uid $AUID}
        fi
        PROG=${EXE##*/}
        PROG=${PROG%.basic}
        PROG=${PROG%.tiny}
        printf '%s\t%s\t%s\n' "$FILE" "$WHO" "${PROG:--}"
    done | sort -u
EOF
chmod 755 /usr/local/lib/serverus-sshnape/audit-changes

cat > /usr/local/bin/security-check << 'SECSCRIPT'
#!/bin/bash
# =============================================================================
# Quick Security Check Script
# Run this to see if anything suspicious happened
# =============================================================================

BOLD='\033[1m'
NC='\033[0m'

# sshd logs under 'sshd', or 'sshd-session' since OpenSSH 9.8. Read the journal
# directly: wtmp (behind `last`) is going away on newer releases.
ssh_log() {
    journalctl -t sshd -t sshd-session --since "$1" --no-pager -o short-iso 2>/dev/null
}

# The verdict: a few lines saying whether anything needs a look. Plain text,
# so the same output works in a terminal and in Telegram (/status).
brief() {
    local WARN=()
    local DAY="24 hours ago"
    local SINCE SETUP_DONE
    # Setup changes SSH keys, config and users itself - count from when it finished
    SINCE=$(date -d "$DAY" +%s)
    SETUP_DONE=$(cat /var/lib/serverus-sshnape/setup-done 2>/dev/null)
    [ "${SETUP_DONE:-0}" -gt "$SINCE" ] 2>/dev/null && SINCE=$SETUP_DONE

    # Changes to who can get in - always worth a look, even when it was you
    local ENTRY KEY LABEL CHANGES FILES BY
    for ENTRY in "authorized_keys:SSH login keys" "ssh_config:SSH server config" "sudoers:sudo rules" \
                 "identity:Users, groups or passwords" "cron:Scheduled jobs (cron)"; do
        KEY=${ENTRY%%:*}
        LABEL=${ENTRY#*:}
        CHANGES=$(/usr/local/lib/serverus-sshnape/audit-changes "$KEY" "$SINCE" "$(date +%s)")
        [ -n "$CHANGES" ] || continue
        FILES=$(echo "$CHANGES" | cut -f1 | grep -vx -- - | sort -u | head -3 | paste -sd, - | sed 's/,/, /g')
        BY=$(echo "$CHANGES" | awk -F'\t' '{print $2 ($3 != "-" ? " using " $3 : "")}' | sort -u | paste -sd';' - | sed 's/;/; /g')
        WARN+=("$LABEL changed${FILES:+: $FILES} (by $BY)")
    done

    local KILLED
    KILLED=$(journalctl -k --since "$DAY" --no-pager -o cat 2>/dev/null | \
        sed -nE 's/.*Killed process [0-9]+ \(([^)]+)\).*/\1/p' | sort -u | paste -sd, -)
    [ -n "$KILLED" ] && WARN+=("Out of memory - killed: $KILLED")

    local DISK
    DISK=$(df -P / | awk 'NR == 2 {gsub("%", "", $5); print $5}')
    [ "$DISK" -ge 90 ] && WARN+=("Disk is ${DISK}% full")

    local FAILED_UNITS
    FAILED_UNITS=$(systemctl --failed --no-legend --plain 2>/dev/null | awk '{print $1}' | paste -sd, -)
    [ -n "$FAILED_UNITS" ] && WARN+=("Failed services: $FAILED_UNITS")

    local FIREWALL="off"
    if ufw status 2>/dev/null | grep -q '^Status: active'; then
        FIREWALL="on"
    fi
    [ "$FIREWALL" = "on" ] || WARN+=("Firewall is off")

    local F2B="on"
    systemctl is-active --quiet fail2ban || { F2B="off"; WARN+=("Fail2ban is not running"); }

    local CLOCK="synced"
    [ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" = "yes" ] || { CLOCK="not synced"; WARN+=("Clock is not synced"); }

    # Informational - logins are counted, not judged
    local LOGIN_COUNT LOGIN_IPS
    LOGIN_COUNT=$(ssh_log "$DAY" | grep -cE 'Accepted [a-z-]+ for ')
    LOGIN_IPS=$(ssh_log "$DAY" | sed -nE 's/.*Accepted [a-z-]+ for [^ ]+ from ([^ ]+) port.*/\1/p' | sort -u | grep -c .)

    local FAILS FAIL_COUNT FAIL_IPS BANNED
    FAILS=$(ssh_log "$DAY" | grep -E 'Invalid user|invalid user|Failed (publickey|password)|authenticating user|maximum authentication attempts')
    FAIL_COUNT=$(printf '%s' "$FAILS" | grep -c .)
    FAIL_IPS=$(echo "$FAILS" | sed -nE 's/.* ([0-9a-fA-F.:]+) port [0-9]+.*/\1/p' | sort -u | grep -c .)
    BANNED=$(fail2ban-client status sshd 2>/dev/null | sed -nE 's/.*Currently banned:\s*([0-9]+).*/\1/p')

    local MEM REBOOT="no reboot pending"
    MEM=$(free -h | awk '/^Mem:/ {m = $3 "/" $2} /^Swap:/ {s = $3} END {print "RAM " m " · swap " s}')
    if [ -f /var/run/reboot-required ]; then
        REBOOT="reboot pending (04:00 UTC)"
    fi

    if [ ${#WARN[@]} -eq 0 ]; then
        echo "✅ All good"
    else
        echo "⚠️ ${#WARN[@]} thing(s) to look at:"
        printf '• %s\n' "${WARN[@]}"
    fi
    echo ""
    echo "🔑 Logins (24h): $LOGIN_COUNT from $LOGIN_IPS IPs"
    echo "🚫 Failed SSH attempts (24h): $FAIL_COUNT from $FAIL_IPS IPs · ${BANNED:-0} banned now"
    echo "🌐 Open ports: $(ss -Hltun 2>/dev/null | awk '{
        n = split($5, a, ":"); port = a[n]; addr = substr($5, 1, length($5) - length(port) - 1)
        if (addr !~ /^127\./ && addr != "[::1]") print $1 "/" port
    }' | sort -t/ -k2 -n -u | paste -sd, - | sed 's/,/, /g')"
    echo "💾 Disk ${DISK}% · $MEM"
    echo "🛡 Firewall $FIREWALL · fail2ban $F2B · clock $CLOCK"
    echo "⏱ $(uptime -p 2>/dev/null) · $REBOOT"
}

if [ "$1" = "--brief" ]; then
    brief
    exit 0
fi

brief
echo ""

echo -e "${BOLD}Logins, last 7 days${NC}"
LOGINS=$(ssh_log "7 days ago" | grep -E 'Accepted (publickey|password|keyboard-interactive)' | tail -10)
echo "${LOGINS:-none}"
echo ""

# With password auth off these are key failures and probes for users that
# don't exist, not "Failed password"
echo -e "${BOLD}Failed SSH attempts, last 24h, top sources${NC}"
FAILS=$(ssh_log "24 hours ago" | grep -E 'Invalid user|invalid user|Failed (publickey|password)|authenticating user|maximum authentication attempts')
if [ -n "$FAILS" ]; then
    echo "$FAILS" | sed -nE 's/.* ([0-9a-fA-F.:]+) port [0-9]+.*/\1/p' | sort | uniq -c | sort -rn | head -5
else
    echo "none"
fi
echo ""

echo -e "${BOLD}Logged in now${NC}"
WHO=$(who)
echo "${WHO:-nobody}"
echo ""

echo -e "${BOLD}Fail2ban${NC}"
if systemctl is-active --quiet fail2ban; then
    for JAIL in sshd recidive; do
        BANNED=$(fail2ban-client status "$JAIL" 2>/dev/null | sed -nE 's/.*Currently banned:\s*([0-9]+).*/\1/p')
        TOTAL=$(fail2ban-client status "$JAIL" 2>/dev/null | sed -nE 's/.*Total banned:\s*([0-9]+).*/\1/p')
        [ -n "$BANNED" ] && echo "$JAIL: $BANNED banned now, $TOTAL total"
    done
else
    echo "not running"
fi
echo ""

echo -e "${BOLD}User changes today (audit)${NC}"
EVENTS=$(ausearch --input-logs -k user_modification -ts today -i 2>/dev/null | grep "type=SYSCALL" | tail -5)
echo "${EVENTS:-none}"
echo ""

echo -e "${BOLD}SSH key changes today (audit)${NC}"
EVENTS=$(/usr/local/lib/serverus-sshnape/audit-changes authorized_keys "$(date -d 00:00 +%s)" "$(date +%s)" | \
    awk -F'\t' '{print $1 " - by " $2 " using " $3}')
echo "${EVENTS:-none}"
echo ""

echo -e "${BOLD}Listening${NC}"
ss -tlnp | grep LISTEN
echo ""

echo -e "${BOLD}Firewall${NC}"
ufw status | head -10
echo ""

echo "More: journalctl -t sshd -t sshd-session -f · ausearch -k authorized_keys -i · aureport --login"
SECSCRIPT

chmod 755 /usr/local/bin/security-check

# Older runs of this script left a copy in /root. Replace it with a symlink so
# both paths keep working.
if [ -e /root/security-check.sh ] && [ ! -L /root/security-check.sh ]; then
    rm -f /root/security-check.sh
fi
ln -sfn /usr/local/bin/security-check /root/security-check.sh

ok "security-check installed"

# -------------------------------------------------------------------------
# Disable unnecessary services
# -------------------------------------------------------------------------

# List of services to disable if they exist
SERVICES_TO_DISABLE="cups avahi-daemon rpcbind nfs-server"

for service in $SERVICES_TO_DISABLE; do
    if systemctl list-unit-files | grep -q "^${service}"; then
        systemctl disable "$service" > /dev/null 2>&1 || true
        systemctl stop "$service" > /dev/null 2>&1 || true
    fi
done

# -------------------------------------------------------------------------
# Quiet login message
# -------------------------------------------------------------------------
# Ubuntu's login banner advertises Ubuntu Pro, ESM and docs links on every
# login. Turn those parts off; updates pending, reboot required and new
# release stay. chmod -x is how update-motd parts are meant to be disabled.
for part in 10-help-text 50-motd-news 88-esm-announce 91-contract-ua-esm-status 90-updates-available; do
    [ -f "/etc/update-motd.d/$part" ] && chmod -x "/etc/update-motd.d/$part"
done
[ -f /etc/default/motd-news ] && sed -i 's/^ENABLED=.*/ENABLED=0/' /etc/default/motd-news
systemctl disable --now motd-news.timer > /dev/null 2>&1 || true
command -v pro > /dev/null 2>&1 && pro config set apt_news=false > /dev/null 2>&1 || true

# The update count, minus the ESM lines Ubuntu mixes into it
cat > /etc/update-motd.d/90-serverus-sshnape-updates << 'EOF'
#!/bin/sh
# Managed by serverus-sshnape: 90-updates-available without the ESM ads
stamp=/var/lib/update-notifier/updates-available
[ -r "$stamp" ] || exit 0
grep -viE 'esm|expanded security|pro status' "$stamp" | cat -s
EOF
chmod 755 /etc/update-motd.d/90-serverus-sshnape-updates
ok "Login message: no Ubuntu Pro ads"

# -------------------------------------------------------------------------
# Lock root password
# -------------------------------------------------------------------------
passwd -l root > /dev/null 2>&1
ok "Root password locked"

# Root isn't always the only way in: cloud images come with a default user
# ("ubuntu"), usually with passwordless sudo
OTHERS=$(awk -F: '$3 >= 1000 && $3 < 65000 && $7 !~ /(nologin|false)$/ {print $1 ":" $6}' /etc/passwd | \
    while IFS=: read -r ACCOUNT HOME_DIR; do
        if grep -qsE '^[[:space:]]*[^#[:space:]]' "$HOME_DIR/.ssh/authorized_keys" "$HOME_DIR/.ssh/authorized_keys2"; then
            echo "$ACCOUNT"
        fi
    done | paste -sd, - | sed 's/,/, /g')
if [ -n "$OTHERS" ]; then
    warn "Can also log in with an SSH key: $OTHERS. Not yours? Empty their ~/.ssh/authorized_keys"
fi

# -------------------------------------------------------------------------
# Telegram alerts
# -------------------------------------------------------------------------
# Runs last: every file this script touches is audited, and the watcher's
# starting point is set below, so none of our own changes get reported.
if [ -n "$TG_TOKEN" ]; then
    mkdir -p /etc/serverus-sshnape
    TG_LABEL=$(hostname -s 2>/dev/null || hostname)
    ( umask 077; printf 'TG_TOKEN=%q\nTG_CHAT=%q\nTG_LABEL=%q\n' "$TG_TOKEN" "$TG_CHAT" "$TG_LABEL" > /etc/serverus-sshnape/telegram.env )
fi

# Also refreshed on plain re-runs, so a box that already has alerts keeps them
if [ -f /etc/serverus-sshnape/telegram.env ]; then
    mkdir -p /usr/local/lib/serverus-sshnape /var/lib/serverus-sshnape

    cat > /usr/local/bin/send-alert << 'EOF'
#!/bin/bash
# Send a Telegram alert: send-alert "backup failed"
# Exits non-zero if the message didn't go out.
CONF=/etc/serverus-sshnape/telegram.env
[ -r "$CONF" ] || { echo "Alerts not configured ($CONF missing)" >&2; exit 1; }
[ $# -gt 0 ] || { echo "Usage: send-alert <message>" >&2; exit 1; }
. "$CONF"
curl -sf --max-time 10 -o /dev/null \
    --data-urlencode "chat_id=$TG_CHAT" \
    --data-urlencode "text=[$TG_LABEL] $*" \
    "https://api.telegram.org/bot$TG_TOKEN/sendMessage"
EOF
    chmod 755 /usr/local/bin/send-alert

    # SSH logins, via PAM. Only new IPs alert: your own logins and deploys
    # (Kamal connects several times per deploy) go quiet after the first.
    cat > /usr/local/lib/serverus-sshnape/login-alert << 'EOF'
#!/bin/bash
# Called by pam_exec when an SSH session opens. Must never block or fail a
# login, so all the work happens in the background and this exits at once.
[ "$PAM_TYPE" = "open_session" ] || exit 0
# PAM doesn't promise a PATH
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
(
    KNOWN=/var/lib/serverus-sshnape/known-ips
    IP="${PAM_RHOST:-unknown}"
    NOW=$(date +%s)
    MONTH=2592000

    exec 9> "$KNOWN.lock"
    flock -w 5 9 || exit 0
    touch "$KNOWN"
    LAST=$(awk -v ip="$IP" '$1 == ip {print $2}' "$KNOWN")
    # Refresh this IP, forget any not seen for a month
    awk -v ip="$IP" -v now="$NOW" -v month="$MONTH" '$1 != ip && now - $2 < month' "$KNOWN" > "$KNOWN.tmp"
    echo "$IP $NOW" >> "$KNOWN.tmp"
    mv "$KNOWN.tmp" "$KNOWN"

    if [ -z "$LAST" ] || [ $((NOW - LAST)) -ge "$MONTH" ]; then
        /usr/local/bin/send-alert "🔑 SSH login from a new IP"
    fi
) < /dev/null > /dev/null 2>&1 &
exit 0
EOF
    chmod 755 /usr/local/lib/serverus-sshnape/login-alert

    # 'optional' + quiet: if the hook breaks, logins carry on regardless
    PAM_LINE="session optional pam_exec.so quiet /usr/local/lib/serverus-sshnape/login-alert"
    grep -qxF "$PAM_LINE" /etc/pam.d/sshd || echo "$PAM_LINE" >> /etc/pam.d/sshd

    # Everything else is checked once a minute
    cat > /usr/local/lib/serverus-sshnape/watch << 'EOF'
#!/bin/bash
# Runs every minute from serverus-sshnape-watch.timer. Collects anything critical
# since the last run into one Telegram message.
STATE=/var/lib/serverus-sshnape
MSG=""
NOW=$(date +%s)

# Changes to the files that decide who gets in. auditd records them; each run
# reads the window from where the last one stopped to a few seconds ago, which
# leaves time for auditd to finish writing the newest events.
# Not ausearch --checkpoint: it saves the last event of any kind, then can't
# find it again under -k, and silently discards everything after it.
AUDIT_FROM=$(cat "$STATE/audit.since" 2>/dev/null)
AUDIT_TO=$((NOW - 5))
if [ -n "$AUDIT_FROM" ] && [ "$AUDIT_FROM" -lt "$AUDIT_TO" ]; then
    for KEY in authorized_keys ssh_config sudoers identity cron; do
        CHANGES=$(/usr/local/lib/serverus-sshnape/audit-changes "$KEY" "$AUDIT_FROM" "$AUDIT_TO")
        [ -n "$CHANGES" ] || continue
        FILES=$(echo "$CHANGES" | cut -f1 | grep -vx -- - | sort -u)
        BY=$(echo "$CHANGES" | awk -F'\t' '{print $2 ($3 != "-" ? " using " $3 : "")}' | sort -u | paste -sd';' - | sed 's/;/; /g')
        case $KEY in
            authorized_keys)
                # Whose keys: the owner of the home directory the file sits in
                OWNERS=$(echo "$FILES" | while read -r FILE; do stat -c %U "${FILE%/.ssh/*}" 2>/dev/null; done | \
                    sort -u | paste -sd, - | sed 's/,/, /g')
                OWNERS=${OWNERS:-an account}
                HEAD="🔑 SSH login keys changed for $OWNERS"; FALLBACK="~/.ssh/authorized_keys"
                IFNOT="Not you? Someone can now log in as $OWNERS. Check the file and remove any key you don't know, right away." ;;
            ssh_config) HEAD="⚙️ SSH server config changed"; FALLBACK=/etc/ssh/
                IFNOT="Not you? Someone may be opening a way in, like turning password login back on." ;;
            sudoers) HEAD="👑 sudo rules changed"; FALLBACK=/etc/sudoers
                IFNOT="Not you? Someone may be giving an account full root rights." ;;
            identity) HEAD="👤 Users, groups or passwords changed"; FALLBACK="/etc/passwd, /etc/shadow or /etc/group"
                IFNOT="Not you? Someone may have added an account or set a password to get back in." ;;
            cron) HEAD="⏰ Scheduled jobs (cron) changed"; FALLBACK=/etc/cron*
                IFNOT="Not you? Attackers add cron jobs so they come back even after you kick them out." ;;
        esac
        FILES=$(echo "$FILES" | head -5 | paste -sd, - | sed 's/,/, /g')
        MSG+=$'\n\n'"$HEAD"$'\n'"File: ${FILES:-$FALLBACK}"$'\n'"By: $BY"$'\n'"$IFNOT"
    done
fi
[ -n "$AUDIT_FROM" ] && [ "$AUDIT_FROM" -ge "$AUDIT_TO" ] || echo "$AUDIT_TO" > "$STATE/audit.since"

# Processes killed for running out of memory
SINCE=$(cat "$STATE/kernel.since" 2>/dev/null)
echo "$NOW" > "$STATE/kernel.since"
if [ -n "$SINCE" ] && [ "$SINCE" -lt "$NOW" ]; then
    KILLED=$(journalctl -k --since "@$SINCE" --until "@$((NOW - 1))" --no-pager -o cat 2>/dev/null | \
        sed -nE 's/.*Killed process [0-9]+ \(([^)]+)\).*/\1/p' | sort -u | paste -sd, -)
    [ -n "$KILLED" ] && MSG+=$'\n\n'"💥 Out of memory - killed: $KILLED"
fi

# Something new listening on a reachable address - your new app, or not.
# Loopback-only listeners are skipped. The baseline only grows, so a service
# that restarts doesn't re-alert.
PORTS="$STATE/listen-ports"
CURRENT=$(ss -Hltun 2>/dev/null | awk '{
    n = split($5, a, ":"); port = a[n]; addr = substr($5, 1, length($5) - length(port) - 1)
    if (addr !~ /^127\./ && addr != "[::1]") print $1 "/" port
}' | sort -u)
if [ -f "$PORTS" ]; then
    NEW=$(comm -13 "$PORTS" <(echo "$CURRENT") | paste -sd, - | sed 's/,/, /g')
    if [ -n "$NEW" ]; then
        MSG+=$'\n\n'"🌐 New listening port(s): $NEW"
        sort -u "$PORTS" <(echo "$CURRENT") > "$PORTS.tmp" && mv "$PORTS.tmp" "$PORTS"
    fi
else
    echo "$CURRENT" > "$PORTS"
fi

# Monday morning check-in, so silence can't be mistaken for "all good"
DIGEST="$STATE/digest-sent"
if [ "$(date -u +%u%H)" = "108" ] && { [ ! -f "$DIGEST" ] || [ $((NOW - $(stat -c %Y "$DIGEST"))) -ge 518400 ]; }; then
    /usr/local/bin/send-alert "📅 Weekly check-in
$(/usr/local/bin/security-check --brief)" && touch "$DIGEST"
fi

# Disk almost full - once a day while it stays that way
DISK=$(df -P / | awk 'NR == 2 {gsub("%", "", $5); print $5}')
if [ "$DISK" -ge 90 ]; then
    FLAG="$STATE/disk-alerted"
    if [ ! -f "$FLAG" ] || [ $((NOW - $(stat -c %Y "$FLAG"))) -ge 86400 ]; then
        MSG+=$'\n\n'"💾 Disk is ${DISK}% full"
        touch "$FLAG"
    fi
else
    rm -f "$STATE/disk-alerted"
fi

# Anything that failed to send last time goes out with this batch
PENDING="$STATE/pending"
[ -s "$PENDING" ] && MSG="$(cat "$PENDING")$MSG"
[ -n "$MSG" ] || exit 0
MSG=${MSG:0:3500}
if /usr/local/bin/send-alert "🚨 Needs a look$MSG"; then
    rm -f "$PENDING"
else
    printf '%s' "$MSG" > "$PENDING"
fi
EOF
    chmod 755 /usr/local/lib/serverus-sshnape/watch

    cat > /etc/systemd/system/serverus-sshnape-watch.service << 'EOF'
[Unit]
Description=serverus-sshnape alert checks

[Service]
Type=oneshot
ExecStart=/usr/local/lib/serverus-sshnape/watch
EOF

    cat > /etc/systemd/system/serverus-sshnape-watch.timer << 'EOF'
[Unit]
Description=Run serverus-sshnape alert checks every minute

[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
AccuracySec=5s

[Install]
WantedBy=timers.target
EOF

    # Tells you the 04:00 auto-reboot happened - or that something crashed.
    # Retries because the network may not be fully up yet.
    cat > /etc/systemd/system/serverus-sshnape-boot-alert.service << 'EOF'
[Unit]
Description=Send a Telegram alert when the server boots
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'for i in 1 2 3 4 5 6 7 8 9 10; do /usr/local/bin/send-alert "🔄 Server booted" && exit 0; sleep 10; done'

[Install]
WantedBy=multi-user.target
EOF

    # Answers /status in Telegram. Python because it has to parse Telegram's
    # JSON replies; python3 is already here as a fail2ban dependency.
    cat > /usr/local/lib/serverus-sshnape/bot.py << 'EOF'
#!/usr/bin/env python3
"""Answers /status in Telegram with the security-check verdict.

Only the chat picked during setup gets an answer; everyone else is ignored.
It runs one fixed, read-only command - nothing typed in Telegram is executed.
"""
import json
import subprocess
import time
import urllib.parse
import urllib.request

# Let bash read the env file it wrote with printf %q
TOKEN, CHAT, LABEL = subprocess.check_output(
    ["bash", "-c", '. /etc/serverus-sshnape/telegram.env && printf "%s\\n%s\\n%s" "$TG_TOKEN" "$TG_CHAT" "$TG_LABEL"'],
    universal_newlines=True,
).split("\n")

HELP = "Send /status for a quick health check."


def api(method, params, timeout=20):
    url = "https://api.telegram.org/bot{}/{}".format(TOKEN, method)
    data = urllib.parse.urlencode(params).encode()
    with urllib.request.urlopen(url, data, timeout=timeout) as response:
        return json.loads(response.read().decode())


def reply(text):
    try:
        api("sendMessage", {"chat_id": CHAT, "text": text[:4000]})
    except Exception:
        pass


def status():
    try:
        api("sendChatAction", {"chat_id": CHAT, "action": "typing"})
    except Exception:
        pass
    try:
        out = subprocess.run(
            ["/usr/local/bin/security-check", "--brief"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            universal_newlines=True, timeout=90,
        ).stdout
    except subprocess.TimeoutExpired:
        out = "security-check timed out"
    return "[{}]\n{}".format(LABEL, out.strip())


try:
    api("setMyCommands", {"commands": json.dumps(
        [{"command": "status", "description": "How is the server doing?"}])})
except Exception:
    pass

started = time.time()
offset = None
while True:
    params = {"timeout": 50, "allowed_updates": json.dumps(["message"])}
    if offset is not None:
        params["offset"] = offset
    try:
        updates = api("getUpdates", params, timeout=70).get("result", [])
    except Exception:
        time.sleep(10)
        continue

    for update in updates:
        offset = update["update_id"] + 1
        message = update.get("message") or {}
        if str(message.get("chat", {}).get("id")) != CHAT:
            continue
        # Don't answer a backlog of old messages after a restart or reboot
        if message.get("date", 0) < started - 300:
            continue
        words = (message.get("text") or "").strip().lower().split()
        command = words[0].split("@")[0] if words else ""
        if command in ("/status", "status"):
            reply(status())
        else:
            reply(HELP)
EOF
    chmod 755 /usr/local/lib/serverus-sshnape/bot.py

    cat > /etc/systemd/system/serverus-sshnape-bot.service << 'EOF'
[Unit]
Description=Telegram bot answering /status
Wants=network-online.target
After=network-online.target

[Service]
ExecStart=/usr/bin/python3 /usr/local/lib/serverus-sshnape/bot.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    # Start reading from now, so nothing this script just did is reported.
    # From the next full second: audit times have fractions, and the root
    # password lock a moment ago falls into the second we're in.
    rm -f /var/lib/serverus-sshnape/audit-*.checkpoint
    echo $(( $(date +%s) + 1 )) > /var/lib/serverus-sshnape/audit.since
    date +%s > /var/lib/serverus-sshnape/kernel.since
    rm -f /var/lib/serverus-sshnape/pending

    # Today's listeners are the baseline - only ports that appear later alert
    ss -Hltun 2>/dev/null | awk '{
        n = split($5, a, ":"); port = a[n]; addr = substr($5, 1, length($5) - length(port) - 1)
        if (addr !~ /^127\./ && addr != "[::1]") print $1 "/" port
    }' | sort -u > /var/lib/serverus-sshnape/listen-ports

    # The IP running this script is you - don't alert on its next login
    SETUP_IP="${SSH_CLIENT%% *}"
    if [ -n "$SETUP_IP" ]; then
        touch /var/lib/serverus-sshnape/known-ips
        awk -v ip="$SETUP_IP" '$1 != ip' /var/lib/serverus-sshnape/known-ips > /var/lib/serverus-sshnape/known-ips.tmp
        echo "$SETUP_IP $(date +%s)" >> /var/lib/serverus-sshnape/known-ips.tmp
        mv /var/lib/serverus-sshnape/known-ips.tmp /var/lib/serverus-sshnape/known-ips
    fi

    systemctl daemon-reload
    systemctl enable serverus-sshnape-boot-alert.service > /dev/null 2>&1 || true
    systemctl enable --now serverus-sshnape-watch.timer > /dev/null 2>&1 || true
    systemctl enable serverus-sshnape-bot.service > /dev/null 2>&1 || true
    systemctl restart serverus-sshnape-bot.service > /dev/null 2>&1 || true

    if [ -n "$TG_TOKEN" ]; then
        if /usr/local/bin/send-alert "✅ Server set up. Alerts on: logins from new IPs, changed SSH keys/config/users/sudoers/cron, new listening ports, OOM kills, disk over 90%, reboots. Check-in every Monday. Send /status for a health check."; then
            ok "Telegram: test message sent"
        else
            warn "Telegram: test message failed. On the server: send-alert test"
        fi
    else
        ok "Telegram: kept"
    fi
fi

# Everything above is us. security-check reports changes from here on.
mkdir -p /var/lib/serverus-sshnape
echo $(( $(date +%s) + 1 )) > /var/lib/serverus-sshnape/setup-done

REMOTE_SCRIPT
} | ssh -i "$KEY_PATH" "${SSH_MUX[@]}" "root@$SERVER" bash -s || REMOTE_STATUS=$?

if [ "$REMOTE_STATUS" -ne 0 ]; then
    print_error "Setup stopped before it finished. Every ✔ above is done and stays done."
    echo "  Fix what the line above says and run the script again. Running it twice is safe."
    exit 1
fi

# -----------------------------------------------------------------------------
# Final verification
# -----------------------------------------------------------------------------
print_step "Check"

# Drop the connection opened before sshd was restarted, so this check proves the
# *new* sshd accepts the key. It becomes the master the status check reuses.
ssh "${SSH_MUX[@]}" -O exit "root@$SERVER" 2>/dev/null || true
if ssh -i "$KEY_PATH" "${SSH_MUX[@]}" -o PasswordAuthentication=no -o ConnectTimeout=10 "root@$SERVER" "echo 'success'" &>/dev/null; then
    print_success "ssh root@$SERVER works"
else
    print_error "ssh root@$SERVER failed"
    echo "  The firewall allows 6 connections per 30 seconds. Wait a minute, then: ssh root@$SERVER"
    echo "  Still no? Password login is off now - use your provider's rescue mode."
    FINAL_FAILED=1
fi

# One connection for both checks, not two - see the SSH_MUX note above.
STATUS_OUT=$(ssh -i "$KEY_PATH" "${SSH_MUX[@]}" -o ConnectTimeout=10 "root@$SERVER" '
    FW=$(ufw status 2>/dev/null | head -1 | sed "s/^Status: //")
    echo "FW=${FW:-unknown}"
    echo "F2B=$(systemctl is-active fail2ban 2>/dev/null || echo unknown)"
    echo "FAILED=$(systemctl --failed --no-legend --plain 2>/dev/null | awk "{print \$1}" | paste -sd, -)"
' 2>/dev/null)

FW_STATUS=$(echo "$STATUS_OUT" | sed -n 's/^FW=//p')
F2B_STATUS=$(echo "$STATUS_OUT" | sed -n 's/^F2B=//p')
FAILED_UNITS=$(echo "$STATUS_OUT" | sed -n 's/^FAILED=//p')

if [ -n "$FW_STATUS" ] && [ "$FW_STATUS" != "unknown" ]; then
    print_success "Firewall: $FW_STATUS"
else
    print_warning "Firewall: could not verify"
fi

if [ "$F2B_STATUS" = "active" ]; then
    print_success "Fail2ban: active"
else
    print_warning "Fail2ban: ${F2B_STATUS:-unknown}"
fi

# Nothing this script does fails a unit, so these were broken before we came.
# Shown here so /status isn't the first place you see them.
if [ -n "$FAILED_UNITS" ]; then
    print_warning "Failed services, not ours: $FAILED_UNITS"
    echo "  Look: systemctl status <name>. Harmless? Clear it: systemctl reset-failed <name>"
fi

# -----------------------------------------------------------------------------
# Print summary
# -----------------------------------------------------------------------------
print_step "Done"
echo "Connect:      ssh root@$SERVER"
echo "Key:          $KEY_PATH"
echo "On server:    security-check · fail2ban-client status sshd · aureport --login"
[ -n "$TELEGRAM" ] && echo "Telegram:     /status any time · send-alert \"text\" from your own jobs"
echo ""
echo "1. Back up the key now. It is the only way in; the root password is locked."
echo "   Password managers store SSH keys (1Password, Bitwarden). Lost it: provider's rescue mode."
echo "2. Add an outside uptime check. A dead server can't text you."
echo "3. Publish container ports on 127.0.0.1 behind a reverse proxy. Only 80/443 are open."

[ -z "${FINAL_FAILED:-}" ] || exit 1
