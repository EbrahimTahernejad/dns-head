#!/usr/bin/env bash
# dns-head installer.
#
# Online:
#   curl -fsSL https://raw.githubusercontent.com/EbrahimTahernejad/dns-head/main/install.sh | sudo bash
#
# Offline (binary or tarball already on disk):
#   sudo ./install.sh /path/to/dns-head-vX.Y.Z-linux-amd64.tar.gz
#   sudo ./install.sh /path/to/dns-head-client        # single binary, role auto-detected
#
# Skip the wizard:
#   sudo NO_SETUP=1 ./install.sh
#
# Non-interactive (e.g. piped from curl) — provide answers via env:
#   sudo ROLE=server DOMAIN=example.com PSK=secret LISTEN=:443 \
#        bash -c "$(curl -fsSL https://raw.githubusercontent.com/EbrahimTahernejad/dns-head/main/install.sh)"
#
#   sudo ROLE=client SERVER=1.2.3.4:443 DOMAIN=example.com PSK=secret \
#        CLIENT_MODE=socks5 SOCKS_PORT=1080 \
#        bash -c "$(curl -fsSL https://raw.githubusercontent.com/EbrahimTahernejad/dns-head/main/install.sh)"

set -euo pipefail

GITHUB_REPO="EbrahimTahernejad/dns-head"
PREFIX="${DNSH_PREFIX:-/usr/local/bin}"
VERSION="${DNSH_VERSION:-latest}"

# ---- pretty output ----
if [ -t 1 ] && [ "${NO_COLOR:-0}" != 1 ]; then
  B=$'\033[1m'; D=$'\033[2m'; R=$'\033[0m'
  C_BLU=$'\033[38;5;39m'; C_GRN=$'\033[38;5;78m'
  C_YEL=$'\033[38;5;220m'; C_RED=$'\033[38;5;203m'
  C_PNK=$'\033[38;5;213m'; C_GRY=$'\033[38;5;245m'
else
  B=""; D=""; R=""; C_BLU=""; C_GRN=""; C_YEL=""; C_RED=""; C_PNK=""; C_GRY=""
fi

banner() {
  cat <<EOF
${C_PNK}${B}
   __                __                __
  / /__/ |____  ____/ /__  ____  ____  / /_
 / __  / __ \\/ ___// // / _ \\/ __ \\/ __ \\/ __/
/ /_/ / / / (__  )/    /  __/ /_/ / /_/ / /_
\\__,_/_/ /_/____/_/_/\\___/\\__,_/\\____/\\__/
${R}${C_GRY}        DNS-headered UDP tunnel${R}

EOF
}

step()  { printf "${C_BLU}${B}==>${R} %s\n" "$*"; }
ok()    { printf "${C_GRN}  ✓${R} %s\n" "$*"; }
ask()   { printf "${C_YEL}${B}?${R}  %s" "$*"; }
warn()  { printf "${C_YEL}!!${R}  %s\n" "$*" >&2; }
die()   { printf "${C_RED}xx${R}  %s\n" "$*" >&2; exit 1; }
hr()    { printf "${C_GRY}%s${R}\n" "------------------------------------------------------------"; }

# read from /dev/tty so we work under `curl | bash`
prompt() {
  local q=$1 default=${2:-} var
  local hint=""
  [ -n "$default" ] && hint=" ${C_GRY}[$default]${R}"
  ask "$q$hint: "
  if read -r var < /dev/tty 2>/dev/null; then
    [ -z "$var" ] && var=$default
  else
    var=$default
  fi
  echo "$var"
}

prompt_choice() {
  # prompt_choice "Question" "key1:label1" "key2:label2" ...
  local q=$1; shift
  local keys=()
  printf "${C_YEL}${B}?${R}  %s\n" "$q"
  local i=1
  for opt in "$@"; do
    local key="${opt%%:*}" label="${opt#*:}"
    keys+=("$key")
    printf "    ${C_GRY}%d)${R} ${B}%s${R} ${C_GRY}%s${R}\n" "$i" "$key" "${label:+— $label}"
    i=$((i+1))
  done
  ask "select 1-${#keys[@]} [1]: "
  local n
  if read -r n < /dev/tty 2>/dev/null; then
    :
  else
    n=1
  fi
  [ -z "$n" ] && n=1
  if ! [[ "$n" =~ ^[0-9]+$ ]] || [ "$n" -lt 1 ] || [ "$n" -gt ${#keys[@]} ]; then
    die "invalid choice"
  fi
  echo "${keys[$((n-1))]}"
}

prompt_secret() {
  local q=$1
  ask "$q (input hidden): "
  local var=""
  stty -echo < /dev/tty 2>/dev/null || true
  read -r var < /dev/tty 2>/dev/null || true
  stty echo < /dev/tty 2>/dev/null || true
  echo
  echo "$var"
}

confirm() {
  local q=$1 default=${2:-Y}
  local opts="[Y/n]"; [ "$default" = N ] && opts="[y/N]"
  ask "$q $opts: "
  local a=""
  read -r a < /dev/tty 2>/dev/null || a=$default
  [ -z "$a" ] && a=$default
  case "$a" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    die "must be run as root (try: sudo $0 $*)"
  fi
}

detect_platform() {
  local os arch
  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  case "$os" in
    linux|darwin) ;;
    *) die "unsupported OS: $os" ;;
  esac
  arch=$(uname -m)
  case "$arch" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) die "unsupported arch: $arch" ;;
  esac
  PLATFORM="${os}-${arch}"
}

resolve_latest_tag() {
  local tag
  if command -v curl >/dev/null 2>&1; then
    tag=$(curl -fsSL "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" \
      | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)
  fi
  if [ -z "${tag:-}" ] && command -v git >/dev/null 2>&1; then
    tag=$(git ls-remote --tags --refs "https://github.com/${GITHUB_REPO}.git" \
      | awk -F/ '{print $NF}' | grep -E '^v[0-9]' | sort -V | tail -1)
  fi
  [ -n "${tag:-}" ] || die "could not resolve latest release tag"
  echo "$tag"
}

fetch() {
  local url=$1 out=$2
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 3 -o "$out" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$out" "$url"
  else
    die "neither curl nor wget is installed"
  fi
}

install_binary_file() {
  local src=$1 name
  name=$(basename "$src")
  case "$name" in
    *dns-head-server*) name=dns-head-server ;;
    *dns-head-client*) name=dns-head-client ;;
    *) name=$(basename "$src") ;;
  esac
  install -m 0755 "$src" "$PREFIX/$name"
  ok "installed ${B}$PREFIX/$name${R}"
}

install_from_tarball() {
  local tarball=$1 staging
  staging=$(mktemp -d)
  trap "rm -rf '$staging'" EXIT
  tar -xzf "$tarball" -C "$staging"
  local installed=0
  for f in "$staging"/dns-head-server "$staging"/dns-head-client \
           "$staging"/*/dns-head-server "$staging"/*/dns-head-client; do
    [ -f "$f" ] || continue
    install_binary_file "$f"
    installed=1
  done
  [ "$installed" = 1 ] || die "no dns-head binaries found in $tarball"
}

bump_sysctl() {
  [ "${DNSH_NO_SYSCTL:-0}" = 1 ] && return
  [ "$(uname -s)" = Linux ] || return
  sysctl -wq net.core.rmem_max=134217728      || warn "couldn't set rmem_max"
  sysctl -wq net.core.wmem_max=134217728      || warn "couldn't set wmem_max"
  sysctl -wq net.core.netdev_max_backlog=16384 || true
  if [ -d /etc/sysctl.d ] && [ ! -f /etc/sysctl.d/99-dns-head.conf ]; then
    cat > /etc/sysctl.d/99-dns-head.conf <<'SYSCTL'
# dns-head: allow kcp to actually use the large socket buffers it requests.
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.netdev_max_backlog = 16384
SYSCTL
    ok "wrote /etc/sysctl.d/99-dns-head.conf"
  else
    ok "sysctl bumped"
  fi
}

write_systemd_server() {
  local unit=/etc/systemd/system/dns-head-server.service
  cat > "$unit" <<UNIT
[Unit]
Description=dns-head tunnel server
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=-/etc/default/dns-head-server
ExecStart=$PREFIX/dns-head-server -listen \${LISTEN} -domain \${DOMAIN} -psk \${PSK} -transport \${TRANSPORT}
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
UNIT
  ok "wrote $unit"
}

write_systemd_client() {
  local unit=/etc/systemd/system/dns-head-client.service
  # Each optional flag is its own pre-formatted env var so systemd's
  # word-splitting of ${VAR} doesn't choke on values that contain "=".
  cat > "$unit" <<UNIT
[Unit]
Description=dns-head tunnel client
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=-/etc/default/dns-head-client
ExecStart=/bin/sh -c '$PREFIX/dns-head-client -server "\$SERVER" -domain "\$DOMAIN" -psk "\$PSK" -transport "\$TRANSPORT" \$CLIENT_ARGS'
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
UNIT
  ok "wrote $unit"
}

# ---- setup wizard ----

run_wizard() {
  hr
  step "Setup wizard"

  local ROLE_RAW="${ROLE:-}"
  if [ -z "$ROLE_RAW" ]; then
    ROLE_RAW=$(prompt_choice "What is this machine?" \
      "server:terminates the tunnel, dials targets out to the internet" \
      "client:exposes a local SOCKS5 or TCP forward, pipes to a remote server" \
      "skip:install binaries only, configure later")
  fi
  if [ "$ROLE_RAW" = "skip" ]; then
    ok "skipping configuration"
    return
  fi

  local DOMAIN_V="${DOMAIN:-}"
  [ -z "$DOMAIN_V" ] && DOMAIN_V=$(prompt "DNS name to embed in the wire header (any plausible host)" "www.cloudflare.com")

  local PSK_V="${PSK:-}"
  if [ -z "$PSK_V" ]; then
    PSK_V=$(prompt_secret "Shared secret (PSK) — must match the other side")
    [ -z "$PSK_V" ] && die "PSK cannot be empty"
  fi

  local TRANSPORT_V="${TRANSPORT:-}"
  if [ -z "$TRANSPORT_V" ]; then
    TRANSPORT_V=$(prompt_choice "Reliability transport" \
      "skcp:striped KCP — best throughput (recommended)" \
      "kcp:single-stream KCP" \
      "raw:from-scratch ARQ, no FEC, no CC" \
      "sraw:striped RAW" \
      "quic:QUIC over the DNS header (use only on clean paths)")
  fi

  if [ "$ROLE_RAW" = "server" ]; then
    local LISTEN_V="${LISTEN:-}"
    [ -z "$LISTEN_V" ] && LISTEN_V=$(prompt "UDP listen address (host:port or :port)" ":443")

    cat > /etc/default/dns-head-server <<CONF
# dns-head-server configuration. Edit and 'systemctl restart dns-head-server'.
DOMAIN=$DOMAIN_V
PSK=$PSK_V
LISTEN=$LISTEN_V
TRANSPORT=$TRANSPORT_V
DNSH_SKCP_LANES=16
DNSH_BATCH=1
DNSH_BATCH_QUEUE=1024
CONF
    chmod 600 /etc/default/dns-head-server
    ok "wrote /etc/default/dns-head-server"
    write_systemd_server

    systemctl daemon-reload
    if confirm "Enable and start dns-head-server now?" Y; then
      systemctl enable --now dns-head-server
      sleep 1
      systemctl status dns-head-server --no-pager -l | head -10 || true
    fi
    hr
    ok "${B}server ready${R} on ${B}$LISTEN_V${R} (transport: $TRANSPORT_V)"
    printf "${C_GRY}   share with client:${R} ${B}DOMAIN=$DOMAIN_V PSK=•••••• TRANSPORT=$TRANSPORT_V${R}\n"
    printf "${C_GRY}   logs:${R} journalctl -u dns-head-server -f\n"
    return
  fi

  # ROLE = client
  local SERVER_V="${SERVER:-}"
  [ -z "$SERVER_V" ] && SERVER_V=$(prompt "Server address (host:port)" "")
  [ -z "$SERVER_V" ] && die "server address required"

  local MODE_V="${CLIENT_MODE:-}"
  if [ -z "$MODE_V" ]; then
    MODE_V=$(prompt_choice "Client local interface" \
      "socks5:local SOCKS5 proxy (apps point at it)" \
      "forward:local TCP port → fixed remote target (-L style)" \
      "both:expose SOCKS5 and one or more port-forwards")
  fi

  local CLIENT_ARGS=""
  case "$MODE_V" in
    socks5)
      local SP="${SOCKS_PORT:-}"
      [ -z "$SP" ] && SP=$(prompt "Local SOCKS5 listen address" "127.0.0.1:1080")
      CLIENT_ARGS="-socks $SP"
      LOCAL_DISPLAY="SOCKS5 $SP"
      ;;
    forward)
      local FW="${FORWARD:-}"
      [ -z "$FW" ] && FW=$(prompt "Forward LOCAL=REMOTE (e.g. :8080=example.com:80)" "")
      [ -z "$FW" ] && die "-forward target required"
      CLIENT_ARGS="-forward $FW"
      LOCAL_DISPLAY="forward $FW"
      ;;
    both)
      local SP="${SOCKS_PORT:-}"
      [ -z "$SP" ] && SP=$(prompt "Local SOCKS5 listen address" "127.0.0.1:1080")
      local FW="${FORWARD:-}"
      [ -z "$FW" ] && FW=$(prompt "Forward LOCAL=REMOTE (e.g. :8080=example.com:80)" "")
      CLIENT_ARGS="-socks $SP -forward $FW"
      LOCAL_DISPLAY="SOCKS5 $SP + forward $FW"
      ;;
    *) die "unknown client mode: $MODE_V" ;;
  esac

  cat > /etc/default/dns-head-client <<CONF
# dns-head-client configuration. Edit and 'systemctl restart dns-head-client'.
SERVER=$SERVER_V
DOMAIN=$DOMAIN_V
PSK=$PSK_V
TRANSPORT=$TRANSPORT_V
CLIENT_ARGS=$CLIENT_ARGS
DNSH_SKCP_LANES=16
DNSH_BATCH=1
DNSH_BATCH_QUEUE=1024
CONF
  chmod 600 /etc/default/dns-head-client
  ok "wrote /etc/default/dns-head-client"
  write_systemd_client

  systemctl daemon-reload
  if confirm "Enable and start dns-head-client now?" Y; then
    systemctl enable --now dns-head-client
    sleep 1
    systemctl status dns-head-client --no-pager -l | head -10 || true
  fi
  hr
  ok "${B}client ready${R}: $LOCAL_DISPLAY → $SERVER_V (transport: $TRANSPORT_V)"
  printf "${C_GRY}   logs:${R} journalctl -u dns-head-client -f\n"
}

# ---- main ----

require_root "$@"
detect_platform
banner
step "platform: ${B}${PLATFORM}${R}"

if [ $# -ge 1 ] && [ -e "$1" ]; then
  src=$1
  step "offline install from ${B}$src${R}"
  case "$src" in
    *.tar.gz|*.tgz) install_from_tarball "$src" ;;
    *)              install_binary_file "$src" ;;
  esac
else
  if [ "$VERSION" = "latest" ]; then
    step "resolving latest release tag"
    VERSION=$(resolve_latest_tag)
    ok "$VERSION"
  fi
  asset="dns-head-${VERSION}-${PLATFORM}.tar.gz"
  url="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}/${asset}"
  step "downloading ${B}${asset}${R}"
  tmp=$(mktemp -d)
  trap "rm -rf '$tmp'" EXIT
  fetch "$url" "$tmp/$asset"
  install_from_tarball "$tmp/$asset"
fi

step "tuning kernel UDP buffer caps"
bump_sysctl

if [ "${NO_SETUP:-0}" = 1 ] || [ "$(uname -s)" != Linux ] || ! command -v systemctl >/dev/null 2>&1; then
  hr
  ok "binaries installed. wizard skipped."
  cat <<TIP

${C_GRY}Run manually:${R}
  ${B}dns-head-server${R} -listen :443 -domain DOMAIN -psk SECRET -transport skcp
  ${B}dns-head-client${R} -server HOST:443 -domain DOMAIN -psk SECRET -transport skcp \\
                  -socks 127.0.0.1:1080
                  -forward :8080=example.com:80     # or this, instead/also

TIP
  exit 0
fi

run_wizard
