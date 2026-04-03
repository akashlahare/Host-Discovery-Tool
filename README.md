# 👑 DiscoveryKing v2.0

**Host Discovery + Port Scanner + WAF/CDN Detection**
by **l33tkid** | For authorized use only
\--
<p align="center">
  <img src="https://raw.githubusercontent.com/akashlahare/Host-Discovery-Tool/main/image.png" width="700">
</p>
\---

## Requirements

* Python 3.7 or higher
* No extra packages needed — uses Python standard library only
* SYN scan requires root/sudo (falls back to connect scan automatically)

**Optional packages** (not required):

```
pip install requests dnspython colorama
```

\---

## Installation

```bash
git clone https://github.com/l33tkid/discoveryking
cd discoveryking
chmod +x install.sh
./install.sh

# Or just run directly
python3 discoveryking.py
```

\---

## Usage

```bash
# Interactive menu
python3 discoveryking.py

# Ping sweep
python3 discoveryking.py -ip 192.168.1.0/24
python3 discoveryking.py -ip 192.168.1.1-50
python3 discoveryking.py -ip 192.168.1.1

# Port scan (common ports)
python3 discoveryking.py -ip 192.168.1.1 -p

# Port scan specific ports
python3 discoveryking.py -ip 192.168.1.1 -p -ports 22,80,443,3306

# Port scan a range
python3 discoveryking.py -ip 192.168.1.1 -p -ports 1-1024

# Top 1000 ports
python3 discoveryking.py -ip 192.168.1.1 -p -ports top1000

# Top 1000 + UDP scan
python3 discoveryking.py -ip 192.168.1.1 -p -ports top1000 --udp

# SYN scan (requires root)
sudo python3 discoveryking.py -ip 192.168.1.1 -p --syn

# Probe a website
python3 discoveryking.py -url example.com

# Website + port scan
python3 discoveryking.py -url example.com -p

# Stealth mode
python3 discoveryking.py -ip 192.168.1.1 -p --stealth

# File input
python3 discoveryking.py -f hosts.txt
```

\---

## Flags

|Flag|What it does|
|-|-|
|`-ip 192.168.1.1`|Single IP|
|`-ip 192.168.1.1-50`|Ping/scan last-octet range|
|`-ip 192.168.1.0/24`|Ping/scan CIDR subnet|
|`-url example.com`|HTTP/WAF probe a web target|
|`-f hosts.txt`|Scan IPs or URLs from file|
|`-p`|Enable port scanning|
|`-ports 22,80,443`|Specific ports to scan|
|`-ports 1-1024`|Port range|
|`-ports top100`|Top 100 common ports|
|`-ports top1000`|Top 1000 common ports|
|`-ports all`|All 65535 ports (slow!)|
|`--syn`|SYN / half-open scan (needs root)|
|`--udp`|Also scan common UDP ports|
|`--stealth`|Slow, randomized, low-noise mode|
|`--threads N`|Max concurrent threads (default: 100)|
|`--timeout S`|Socket timeout seconds (default: 2.0)|
|`--retries N`|HTTP retry attempts (default: 3)|
|`--no-banner`|Skip ASCII banner|

\---

## Port Scanner Features

|Feature|How it works|
|-|-|
|**TCP Connect scan**|Full 3-way handshake — no root needed|
|**SYN scan**|Half-open, lower footprint — needs root|
|**UDP scan**|Probes common UDP ports (53, 123, 161, etc.)|
|**Banner grabbing**|Sends protocol probes, reads raw responses|
|**Service fingerprinting**|Regex matching against SSH, HTTP, FTP, MySQL, Redis, SMB, RDP, etc.|
|**Version detection**|Extracts version strings from banners|
|**TLS/SSL info**|Grabs cert CN, org, expiry, cipher suite|
|**OS fingerprinting**|TTL-based OS guess (Linux/Windows/Cisco)|
|**100+ default ports**|Covers all major services out of the box|

\---

## What it detects (WAF/CDN)

* **27 providers** — Cloudflare, Akamai, AWS WAF, Imperva, Sucuri, Fastly, F5, Barracuda, ModSecurity, Wordfence, Azure WAF, Google Cloud Armor, Fortinet, Radware, Reblaze, Varnish, Nginx, Citrix, Wallarm, CloudFront, StackPath, Limelight, and more
* **Rate limiting** (429) — backs off automatically
* **Blocking responses** — retries with rotated headers and User-Agents

\---

## File format for -f

```
# Comments are ignored
192.168.1.1
192.168.1.0/24
10.0.0.1-20
example.com
https://testsite.com
```

\---

## Disclaimer

Only scan systems you own or have explicit permission to test.
Unauthorized scanning may be illegal in your jurisdiction.

