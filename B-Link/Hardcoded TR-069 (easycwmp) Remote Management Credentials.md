**Hardcoded TR-069 (easycwmp) Remote Management Credentials**

> **Severity**: 🔴 CRITICAL  
> **Firmware**: `X-PRO(AC6)_Dual_V1.0.22-20231206-upgrade.bin`  -https://b-link.net.cn/product_29_176.html.html  
> **Device**: B-Link AC1200 (MediaTek MT7621)  
> **Base System**: LEDE 17.01-SNAPSHOT (Linux 4.4.198, mipsel_24kc)  
> **Discovered**: 2026-06-26  
> **Reporter**：@DavCloudz (Yun Zhang)
---

### Summary

The B-Link X-PRO(AC6) firmware includes a pre-configured TR-069 remote management daemon (easycwmp) with **three sets of hardcoded credentials** for local interface, ACS (Auto-Configuration Server), and STUN server access. The configuration also discloses production server URLs and IP addresses. While TR-069 is disabled by default (`option enable '0'`), an attacker who gains any level of access to the admin panel can enable it and use the hardcoded credentials to establish a remote management channel, potentially allowing persistent C2 communication and configuration manipulation from the manufacturer's cloud infrastructure — or a rogue server impersonating it.

---

### Details

**File**: `etc/config/easycwmp`

#### Hardcoded Credential Sets

| Scope | Username | Password | Protocol | Purpose |
|-------|----------|----------|----------|---------|
| **Local interface** | `blink_test` | `blink_test` | HTTP Digest | easycwmp local web interface on port 8001 |
| **ACS server** | `acs` | `acs` | HTTP Basic/Digest | Auto-Configuration Server authentication |
| **STUN server** | `CR$avsystem` | `cr$1q2w#E$R` | STUN | NAT traversal keepalive |

#### Hardcoded Server Endpoints

**ACS Server (Auto-Configuration Server)**:
```
URL:  http://39.106.195.193:9090/ACS-server/ACS/blink_test
Authentication: Basic or Digest
Credentials: acs / acs
```

**STUN Server (NAT Traversal)**:
```
Address: 202.73.99.201:3478
Credentials: CR$avsystem / cr$1q2w#E$R
```

#### Complete Configuration Breakdown

```
config local
    option enable '0'
    option interface eth1
    option port 8001
    option ubus_socket /var/run/ubus.sock
    option username 'blink_test'
    option password 'blink_test'
    option authentication 'Digest'
    option logging_level '3'

config acs
    option url 'http://39.106.195.193:9090/ACS-server/ACS/blink_test'
    option username 'acs'
    option password 'acs'
    option periodic_enable '1'
    option periodic_interval '5'
    option periodic_time '0001-01-01T00:00:00Z'

config stun
    option enable '0'
    option username 'CR$avsystem'
    option password 'cr$1q2w#E$R'
    option server_address '202.73.99.201'
    option server_port '3478'
    option min_keepalive '30'
    option max_keepalive '3600'
    option nat_detected '1'
    option client_port 7547
```

#### Security Implications of TR-069

TR-069 (Technical Report 069) is a CWMP (CPE WAN Management Protocol) that allows:
- Remote configuration and firmware updates by the ISP
- Status monitoring and diagnostics
- Factory reset and reboot commands
- SSH/HTTP session establishment on demand

The following TR-069 RPC methods would be available to an authenticated ACS server:
- `Download` — push firmware updates (no signature verification needed)
- `Upload` — pull configuration backups
- `Reboot` — remotely reboot the device
- `FactoryReset` — reset to factory defaults
- `SetParameterValues` — modify any configuration parameter
- `AddObject`/`DeleteObject` — manipulate configuration objects

#### How easycwmp is Installed

**File**: `etc/init.d/easycwmp` (if exists) or via the `easycwmpd` binary

```
# Start command (from strings):
easycwmpd -f -s /var/run/ubus.sock
```

The easycwmp daemon integrates with ubus, meaning it has access to the same RPC interface as rpcd (C-RTR-07).

---

### Proof of Concept

#### PoC 1: Simulate ACS Server Connection

If TR-069 is enabled on the device (via admin panel compromise or physical access), an attacker controlling the ACS server can authenticate and execute RPC commands:

```bash
# From a machine on the internet (impersonating the ACS server)
# The device at 39.106.195.193:9090 is the legitimate ACS server,
# but the credentials "acs"/"acs" allow anyone who can reach it to
# potentially register as a new CPE or receive device callbacks

# On the router side (if TR-069 is enabled):
# The router will periodically connect to:
# http://39.106.195.193:9090/ACS-server/ACS/blink_test
# Using HTTP Digest authentication with blink_test/blink_test

# An attacker who controls a machine that can intercept or spoof
# DNS for 39.106.195.193 can redirect the TR-069 connection
```

#### PoC 2: Enable TR-069 via Admin Panel Access

```bash
# Step 1: SSH to the router with root credentials (C-RTR-02)
ssh root@192.168.16.1
Password: blinkadmin

# Step 2: Enable TR-069 locally
uci set easycwmp.@local[0].enable='1'
uci commit easycwmp
/etc/init.d/easycwmp start

# Step 3: The router now listens on port 8001 and connects to the ACS server
# The ACS server can issue any TR-069 RPC command
```

#### PoC 3: DNS Spoofing Attack on TR-069

```bash
# If the attacker is on the same LAN:
# Spoof DNS for 39.106.195.193 to redirect to attacker's machine
# The attacker runs a rogue ACS server that authenticates with "acs"/"acs"
# and issues a "Download" RPC to push malicious firmware

# Better: Since the TR-069 connection URL is HTTP (not HTTPS),
# there is no TLS certificate validation:
acs.url = "http://39.106.195.193:9090/ACS-server/ACS/blink_test"
# A MITM attacker can trivially intercept and modify TR-069 traffic
```

---

### Impact

| Dimension | Assessment |
|-----------|------------|
| **CVSS Score** | **9.1 (Critical)** — CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H |
| **Attack Vector** | Network (requires enabling TR-069 or access to admin panel) |
| **Complexity** | High (TR-069 disabled by default) |
| **Privileges Required** | None if MITM on TR-069; Admin panel access if enabling |
| **User Interaction** | None |

#### Confidentiality Impact: HIGH

- ACS server can read all device configuration including passwords
- Configuration upload sends full device state to ACS

#### Integrity Impact: HIGH

- ACS server can push firmware updates (unsigned, MD5 only — see H-RTR-05)
- ACS server can modify any configuration parameter via `SetParameterValues`

#### Availability Impact: HIGH

- ACS server can reboot, factory reset, or brick the device remotely

#### Key Risk Amplifiers

| Risk Factor | Detail |
|-------------|--------|
| **HTTP (not HTTPS)** | TR-069 ACS URL uses `http://`, not `https://`. No TLS means no server identity verification and no transport encryption. All TR-069 traffic is plaintext and trivially interceptable. |
| **Hardcoded credentials** | The `acs`/`acs` pair is trivially guessable and identical across all devices |
| **Known server location** | The ACS server at `39.106.195.193:9090` becomes a high-value target — compromising it compromises all connected devices |
| **STUN credentials for NAT** | The STUN credentials `CR$avsystem`/`cr$1q2w#E$R` bypass NAT for management traffic, creating a persistent tunnel through firewalls |

---

## Combined Exploitation Chain

The two vulnerabilities are synergistic and can be chained for complete device takeover:

### Chain 1: From LAN to C2 Persistence

```
[LAN Access]
    ↓
Root SSH via C-RTR-02 (blinkadmin)
    ↓
Enable TR-069 via UCI
    ↓
Device connects to ACS server (C-RTR-06)
    ↓
ACS server pushes malicious firmware via "Download" RPC
    ↓
Persistent backdoor installed
```

### Chain 2: From Backup Interception to Remote Control

```
[Packet capture on LAN]
    ↓
Intercept backup.cgi response → encrypted tar.gz
    ↓
Decrypt with "blinkadmin" (C-RTR-02 cross-function reuse)
    ↓
Extract full device config including WiFi, PPPoE, VPN
    ↓
Enable TR-069 via recovered admin credentials
    ↓
Establish TR-069 communication (C-RTR-06)
    ↓
Full remote device management
```

### Chain 3: From WAN to Botnet

```
[Internet attacker]
    ↓
Scan for B-Link AC6 devices with exposed web/SSH
    ↓
Attempt root:blinkadmin SSH login (C-RTR-02)
    ↓
Enable TR-069 pointing to attacker-controlled ACS server
    ↓
Install persistent firmware backdoor via TR-069 (C-RTR-06)
    ↓
Device added to botnet
```

---

## Remediation Recommendations

### Immediate (P0)

1. **Generate unique root passwords at first boot** — each device should generate a random password during initial setup, printed on the device label
2. **Remove hardcoded `blinkadmin` from all subsystems** — the backup encryption key, root password, and any firmware verification must use independent secrets
3. **Remove or disable TR-069 by default** — the service should not be included in consumer router firmware; if required, use per-device certificates and TLS
4. **Remove hardcoded ACS/STUN credentials** — if TR-069 is necessary, credentials must be provisioned per-device by the ISP
