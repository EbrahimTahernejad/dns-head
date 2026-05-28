# dns-head

A UDP tunnel whose datagrams look like DNS queries on the wire. The header
format is byte-for-byte compatible with Xray-core's
[`headers/dns`](https://github.com/XTLS/Xray-core/tree/main/transport/internet/headers/dns)
prefix; the reliability/encryption layer underneath is pluggable.

Built because mKCP's ARQ-with-duplication is wasteful on modern links and
QUIC's Cubic congestion control collapses under the kind of loss-plus-shaping
typical of geoblocked paths. Packaged transports cover the tradeoff space:

| `-transport` | What it is | When to pick it |
|---|---|---|
| `quic`  | quic-go over the DNS header | clean, low-loss paths |
| `kcp`   | kcp-go in blast mode (`nc=1`, no FEC), wrapped by smux v2 | lossy / shaped paths, single stream |
| `raw`   | our own reliable byte transport (SACK, Karn, no CC), wrapped by smux v2 | educational, KCP-free baseline |
| **`skcp`**  | **striped KCP: N parallel KCP sessions, bytes RR'd, default** | **best throughput on per-flow-capped paths** |
| `sraw`  | striped RAW (same striping logic over `raw`) | mainly for completeness |

The same binary serves both ends — pick a role with the cmd and `-transport`.

## Install

### Curl one-liner

```
curl -fsSL https://raw.githubusercontent.com/EbrahimTahernejad/dns-head/main/install.sh | sudo bash
```

Drops you into an interactive wizard that asks role (server / client),
chooses between **SOCKS5** or **TCP port-forward** (or both), and writes the
right systemd unit + `/etc/default/dns-head-*` for you.

### Offline install

You already have the binary or tarball on disk:

```
sudo ./install.sh /path/to/dns-head-v1.0.0-linux-amd64.tar.gz
# or a single binary, role auto-detected from the filename:
sudo ./install.sh /path/to/dns-head-server
```

### Skip the wizard

```
sudo NO_SETUP=1 ./install.sh
```

### Non-interactive (preseed everything via env)

```
# server side
sudo ROLE=server DOMAIN=example.com PSK=$(openssl rand -base64 24) LISTEN=:443 \
  bash -c "$(curl -fsSL https://raw.githubusercontent.com/EbrahimTahernejad/dns-head/main/install.sh)"

# client side, SOCKS5 mode
sudo ROLE=client SERVER=1.2.3.4:443 DOMAIN=example.com PSK=secret \
     CLIENT_MODE=socks5 SOCKS_PORT=127.0.0.1:1080 \
  bash -c "$(curl -fsSL https://raw.githubusercontent.com/EbrahimTahernejad/dns-head/main/install.sh)"

# client side, fixed port-forward (e.g. local :2222 → remote dev-box:22)
sudo ROLE=client SERVER=1.2.3.4:443 DOMAIN=example.com PSK=secret \
     CLIENT_MODE=forward FORWARD=":2222=dev-box.internal:22" \
  bash -c "$(curl -fsSL https://raw.githubusercontent.com/EbrahimTahernejad/dns-head/main/install.sh)"
```

| env | purpose |
|---|---|
| `ROLE` | `server` \| `client` \| `skip` |
| `DOMAIN` | DNS name in the wire header |
| `PSK` | shared secret |
| `TRANSPORT` | one of: `skcp` `kcp` `raw` `sraw` `quic` (default `skcp`) |
| `LISTEN` | server's UDP listen address |
| `SERVER` | client's remote server (host:port) |
| `CLIENT_MODE` | `socks5` \| `forward` \| `both` |
| `SOCKS_PORT` | client's local SOCKS5 address (e.g. `127.0.0.1:1080`) |
| `FORWARD` | `LOCAL=REMOTE` pair (e.g. `:2222=devbox:22`) |
| `DNSH_VERSION` | pin a release |
| `DNSH_PREFIX` | install dir (default `/usr/local/bin`) |
| `DNSH_NO_SYSCTL` | skip kernel buffer tuning |

## Run manually (no systemd)

```bash
# server
dns-head-server -listen :443 -domain www.cloudflare.com -psk SECRET -transport skcp

# client (SOCKS5)
dns-head-client -server HOST:443 -domain www.cloudflare.com -psk SECRET -transport skcp \
                -socks 127.0.0.1:1080

# client (port forward — local :2222 to remote dev-box:22)
dns-head-client -server HOST:443 -domain www.cloudflare.com -psk SECRET -transport skcp \
                -forward :2222=dev-box.internal:22

# client (both, plus multiple forwards)
dns-head-client -server HOST:443 -domain www.cloudflare.com -psk SECRET -transport skcp \
                -socks 127.0.0.1:1080 \
                -forward :8080=example.com:80 \
                -forward :2222=dev-box:22
```

## Tunables

```
DNSH_BATCH=1                       # batched sendmmsg (default on Linux)
DNSH_BATCH_QUEUE=1024              # outgoing queue depth before back-pressure

# skcp / sraw
DNSH_SKCP_LANES=16                 # parallel KCP sessions for striping (default 16)
DNSH_SRAW_LANES=16                 # ditto for sraw

# kcp / skcp internals (kcp-go knobs)
DNSH_KCP_MTU=1250
DNSH_KCP_SNDWND=2048
DNSH_KCP_RCVWND=2048
DNSH_KCP_TTI=10
DNSH_KCP_RESEND=2
DNSH_KCP_DATASHARDS=0              # set with PARITYSHARDS for FEC
DNSH_KCP_PARITYSHARDS=0

# raw / sraw internals
DNSH_RAW_WINDOW=4096               # sender in-flight cap (segments)
DNSH_RAW_RECVBUDGET=8192           # receiver out-of-order buffer cap
DNSH_RAW_MAXRETX=256               # retransmits per 20 ms tick
```

## Build from source

```
go build ./cmd/dns-head-server ./cmd/dns-head-client
```

Cross-compile:

```
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags='-s -w' \
   ./cmd/dns-head-server ./cmd/dns-head-client
```

## Releasing

Push a tag matching `v*`. The release workflow at
`.github/workflows/release.yml` builds linux/darwin/windows × amd64/arm64,
packages each as `dns-head-vX.Y.Z-OS-ARCH.tar.gz` (or `.zip` on Windows),
generates `SHA256SUMS`, and attaches everything to a GitHub release.

```
git tag v0.1.0
git push origin v0.1.0
```
