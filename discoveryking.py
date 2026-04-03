#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════╗
               DiscoveryKing  v2.0  — by l33tkid                 
      Host Discovery + WAF/CDN Detection + Evasion Engine        
╚═══════════════════════════════════════════════════════════════╝
"""

import os
import platform
import subprocess
import threading
import ipaddress
import time
import random
import socket
import argparse
import sys
import re
import json
from datetime import datetime
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from urllib.parse import urlparse

# ─────────────────────────────────────────────
#  ANSI COLOR PALETTE
# ─────────────────────────────────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"

    # Foregrounds
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    ORANGE  = "\033[38;5;214m"
    PINK    = "\033[38;5;213m"
    TEAL    = "\033[38;5;44m"
    LIME    = "\033[38;5;154m"
    GOLD    = "\033[38;5;220m"
    PURPLE  = "\033[38;5;177m"
    CORAL   = "\033[38;5;203m"

    # Backgrounds
    BG_RED    = "\033[41m"
    BG_GREEN  = "\033[42m"
    BG_BLUE   = "\033[44m"
    BG_DARK   = "\033[40m"

    @staticmethod
    def strip(text):
        ansi_escape = re.compile(r'\033\[[0-9;]*m')
        return ansi_escape.sub('', text)

# ─────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────
BANNER = f"""
{C.CYAN}{C.BOLD}
  ██████╗ ██╗███████╗ ██████╗ ██████╗ ██╗   ██╗███████╗██████╗ ██╗   ██╗
  ██╔══██╗██║██╔════╝██╔════╝██╔═══██╗██║   ██║██╔════╝██╔══██╗╚██╗ ██╔╝
  ██║  ██║██║███████╗██║     ██║   ██║██║   ██║█████╗  ██████╔╝ ╚████╔╝ 
  ██║  ██║██║╚════██║██║     ██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗  ╚██╔╝  
  ██████╔╝██║███████║╚██████╗╚██████╔╝ ╚████╔╝ ███████╗██║  ██║   ██║   
  ╚═════╝ ╚═╝╚══════╝ ╚═════╝ ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝   ╚═╝  
{C.GOLD}
         ██╗  ██╗██╗███╗   ██╗ ██████╗ 
         ██║ ██╔╝██║████╗  ██║██╔════╝ 
         █████╔╝ ██║██╔██╗ ██║██║  ███╗
         ██╔═██╗ ██║██║╚██╗██║██║   ██║
         ██║  ██╗██║██║ ╚████║╚██████╔╝
         ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝{C.RESET}

{C.MAGENTA}  ╔══════════════════════════════════════════════════════════════════╗
           Host Discovery  +  WAF/CDN Detection Engine  v2.0         
  ╚══════════════════════════════════════════════════════════════════╝{C.RESET}
  ╔══════════════════════════════════════════════════════════════════╗
{C.DIM}              by {C.LIME}l33tkid{C.RESET}{C.DIM}  |  for authorized use only{C.RESET}
  ╚══════════════════════════════════════════════════════════════════╝

"""

# ─────────────────────────────────────────────
#  LOGGER (thread-safe)
# ─────────────────────────────────────────────
_print_lock = threading.Lock()

def log(tag, msg, color=C.WHITE, tag_color=None):
    tc = tag_color or color
    ts = f"{C.DIM}{datetime.now().strftime('%H:%M:%S')}{C.RESET}"
    with _print_lock:
        print(f" {ts}  {tc}{C.BOLD}{tag}{C.RESET}  {color}{msg}{C.RESET}")

def log_info(msg):    log("[*]", msg, C.CYAN)
def log_ok(msg):      log("[+]", msg, C.GREEN)
def log_warn(msg):    log("[!]", msg, C.YELLOW, C.ORANGE)
def log_error(msg):   log("[-]", msg, C.RED)
def log_retry(msg):   log("[~]", msg, C.MAGENTA)
def log_detect(msg):  log("[!]", msg, C.ORANGE, C.ORANGE)
def log_host(ip, msg, color): log(f"[{ip}]", msg, color)
def log_stealth(msg): log("[S]", msg, C.TEAL)
def log_rate(msg):    log("[⚠]", msg, C.YELLOW, C.GOLD)

def print_separator(char="─", length=75, color=C.DIM):
    with _print_lock:
        print(f"{color}{char * length}{C.RESET}")

def print_section(title, color=C.CYAN):
    print_separator()
    with _print_lock:
        pad = (73 - len(C.strip(title))) // 2
        print(f"{color}{C.BOLD}{' ' * pad}{title}{C.RESET}")
    print_separator()

# ─────────────────────────────────────────────
#  WAF / CDN FINGERPRINT DATABASE  (25+ providers)
# ─────────────────────────────────────────────
WAF_SIGNATURES = {
    "Cloudflare": {
        "headers":  ["cf-ray", "cf-cache-status", "cf-request-id", "cf-connecting-ip"],
        "keywords": ["cloudflare", "attention required", "one moment", "ray id", "cf-ray"],
        "codes":    [403, 429, 503],
        "server":   ["cloudflare"],
        "color":    C.ORANGE,
    },
    "Akamai": {
        "headers":  ["x-akamai-transformed", "x-check-cacheable", "akamai-origin-hop", "x-akamai-request-id"],
        "keywords": ["akamai", "reference #", "access denied by akamai"],
        "codes":    [403],
        "server":   ["akamaighost", "akamai"],
        "color":    C.BLUE,
    },
    "AWS WAF": {
        "headers":  ["x-amzn-requestid", "x-amz-cf-id", "x-amz-id-2", "x-amz-apigw-id"],
        "keywords": ["aws waf", "403 forbidden", "request blocked by aws"],
        "codes":    [403],
        "server":   ["awselb", "aws"],
        "color":    C.YELLOW,
    },
    "Imperva (Incapsula)": {
        "headers":  ["x-iinfo", "x-cdn", "incap-ses", "visid_incap"],
        "keywords": ["incapsula", "imperva", "request unsuccessful", "_incapsula_"],
        "codes":    [403, 406],
        "server":   ["incapsula"],
        "color":    C.CYAN,
    },
    "Fastly": {
        "headers":  ["x-fastly-request-id", "fastly-restarts", "x-served-by", "x-cache"],
        "keywords": ["fastly", "varnish cache server", "fastly error"],
        "codes":    [503],
        "server":   ["fastly"],
        "color":    C.RED,
    },
    "Sucuri": {
        "headers":  ["x-sucuri-id", "x-sucuri-cache", "x-sucuri-block"],
        "keywords": ["sucuri", "access denied - sucuri", "website firewall"],
        "codes":    [403, 406],
        "server":   ["sucuri"],
        "color":    C.GREEN,
    },
    "F5 BIG-IP ASM": {
        "headers":  ["x-waf-event-info", "x-cnection", "asm_request_status"],
        "keywords": ["the requested url was rejected", "please consult with your administrator", "f5 networks"],
        "codes":    [403],
        "server":   ["bigip", "f5"],
        "color":    C.MAGENTA,
    },
    "Barracuda WAF": {
        "headers":  ["x-bwf-request-id"],
        "keywords": ["barracuda", "barracuda networks", "invalid url"],
        "codes":    [400, 403],
        "server":   ["barracuda"],
        "color":    C.LIME,
    },
    "ModSecurity": {
        "headers":  ["x-modsec-ruleid"],
        "keywords": ["mod_security", "modsecurity", "not acceptable", "406 not acceptable"],
        "codes":    [403, 406],
        "server":   ["mod_security", "modsec"],
        "color":    C.CORAL,
    },
    "Wordfence": {
        "headers":  [],
        "keywords": ["wordfence", "generated by wordfence", "your access to this site has been limited"],
        "codes":    [403],
        "server":   [],
        "color":    C.TEAL,
    },
    "Palo Alto PAN-OS": {
        "headers":  ["x-pan-rec"],
        "keywords": ["pan-os", "palo alto", "site blocked"],
        "codes":    [403],
        "server":   ["pan"],
        "color":    C.GOLD,
    },
    "Fortinet FortiWeb": {
        "headers":  ["forticlient-request-id", "fortiwaf"],
        "keywords": ["fortinet", "fortiweb", "fortigate", "your request is blocked"],
        "codes":    [403],
        "server":   ["fortinet", "fortigate"],
        "color":    C.RED,
    },
    "Radware AppWall": {
        "headers":  ["x-sl-compstate"],
        "keywords": ["radware", "appwall", "unauthorized activity has been detected"],
        "codes":    [403],
        "server":   ["radware"],
        "color":    C.PINK,
    },
    "Reblaze": {
        "headers":  ["x-reblaze-protection", "rbzid"],
        "keywords": ["reblaze", "transaction id:"],
        "codes":    [403],
        "server":   ["reblaze"],
        "color":    C.PURPLE,
    },
    "DenyAll": {
        "headers":  ["x-denyall-session"],
        "keywords": ["denyall", "denied by denyall"],
        "codes":    [403],
        "server":   ["denyall"],
        "color":    C.CORAL,
    },
    "Varnish Cache": {
        "headers":  ["x-varnish", "via"],
        "keywords": ["varnish", "cache hit", "cache miss"],
        "codes":    [503],
        "server":   ["varnish"],
        "color":    C.CYAN,
    },
    "Nginx WAF": {
        "headers":  [],
        "keywords": ["nginx", "400 bad request", "403 forbidden"],
        "codes":    [403, 400],
        "server":   ["nginx"],
        "color":    C.GREEN,
    },
    "Citrix NetScaler": {
        "headers":  ["ns_af", "citrix_ns_id", "x-nsprotect"],
        "keywords": ["citrix", "netscaler", "ns transaction id"],
        "codes":    [403],
        "server":   ["netscaler", "citrix"],
        "color":    C.BLUE,
    },
    "Wallarm": {
        "headers":  ["x-wallarm-node"],
        "keywords": ["wallarm", "request blocked by wallarm"],
        "codes":    [403],
        "server":   ["wallarm"],
        "color":    C.LIME,
    },
    "Microsoft Azure WAF": {
        "headers":  ["x-ms-request-id", "x-azure-ref"],
        "keywords": ["azure", "microsoft", "403 forbidden - azure"],
        "codes":    [403],
        "server":   ["microsoft-iis", "azure"],
        "color":    C.BLUE,
    },
    "Google Cloud Armor": {
        "headers":  ["x-goog-request-params", "x-gfe-request-id"],
        "keywords": ["google", "cloud armor", "403 forbidden by google"],
        "codes":    [403],
        "server":   ["google frontend", "gfe"],
        "color":    C.YELLOW,
    },
    "Cloudfront (AWS CDN)": {
        "headers":  ["x-amz-cf-pop", "x-cache"],
        "keywords": ["cloudfront", "error from cloudfront", "request blocked"],
        "codes":    [403, 503],
        "server":   ["cloudfront"],
        "color":    C.ORANGE,
    },
    "Kona SiteDefender (Akamai)": {
        "headers":  ["x-check-cacheable"],
        "keywords": ["kona", "sitedefender", "akamai"],
        "codes":    [403],
        "server":   ["akamai"],
        "color":    C.MAGENTA,
    },
    "Comodo WAF": {
        "headers":  ["x-protected-by"],
        "keywords": ["comodo", "comodo waf", "protected by comodo"],
        "codes":    [403],
        "server":   ["comodo"],
        "color":    C.TEAL,
    },
    "SiteLock": {
        "headers":  ["x-sitelock-request-id"],
        "keywords": ["sitelock", "website protected by sitelock"],
        "codes":    [403],
        "server":   ["sitelock"],
        "color":    C.PINK,
    },
    "StackPath": {
        "headers":  ["x-sp-url", "x-sp-waf"],
        "keywords": ["stackpath", "maxcdn", "access denied by stackpath"],
        "codes":    [403],
        "server":   ["stackpath"],
        "color":    C.GOLD,
    },
    "Limelight CDN": {
        "headers":  ["x-llnw-source"],
        "keywords": ["limelight", "llnw"],
        "codes":    [503],
        "server":   ["limelight"],
        "color":    C.LIME,
    },
}

BLOCKING_KEYWORDS = [
    "access denied", "request blocked", "forbidden", "not acceptable",
    "security check", "ddos protection", "please enable javascript",
    "unusual activity", "captcha", "bot detected", "automated request",
    "rate limit", "too many requests", "your ip has been blocked",
]

# ─────────────────────────────────────────────
#  USER-AGENT POOL
# ─────────────────────────────────────────────
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.105 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "curl/8.6.0",
    "python-requests/2.31.0",
]

DECOY_IPS = [
    "8.8.8.8", "1.1.1.1", "208.67.222.222", "64.6.64.6",
    "198.41.0.4", "192.5.5.241", "192.203.230.10",
]

# ─────────────────────────────────────────────
#  STATISTICS
# ─────────────────────────────────────────────
class Stats:
    def __init__(self):
        self.lock       = threading.Lock()
        self.reachable  = 0
        self.unreachable= 0
        self.waf_detected=0
        self.rate_limited=0
        self.retried    = 0
        self.open_ports = 0
        self.start_time = time.time()

    def elapsed(self):
        return round(time.time() - self.start_time, 2)

STATS = Stats()

# ─────────────────────────────────────────────
#  WAF DETECTION ENGINE
# ─────────────────────────────────────────────
def detect_waf(response_headers: dict, response_body: str = "", status_code: int = 200):
    """
    Analyzes HTTP response for WAF/CDN fingerprints.
    Returns list of (provider_name, color) tuples detected.
    """
    detected = []
    headers_lower = {k.lower(): v.lower() for k, v in response_headers.items()}
    body_lower = response_body.lower()
    server_val = headers_lower.get("server", "")

    for provider, sig in WAF_SIGNATURES.items():
        score = 0

        # Check response headers
        for h in sig["headers"]:
            if h.lower() in headers_lower:
                score += 2

        # Check server header
        for sv in sig.get("server", []):
            if sv in server_val:
                score += 2

        # Check body keywords
        for kw in sig["keywords"]:
            if kw in body_lower:
                score += 1

        # Check status codes
        if status_code in sig["codes"]:
            score += 1

        if score >= 2:
            detected.append((provider, sig["color"]))

    return detected

def is_blocking_response(status_code, response_body=""):
    """Check if response indicates blocking (regardless of WAF)."""
    if status_code in [403, 406, 429]:
        return True
    body_lower = response_body.lower()
    return any(kw in body_lower for kw in BLOCKING_KEYWORDS)

# ═════════════════════════════════════════════
#  PORT SCANNER ENGINE
# ═════════════════════════════════════════════

# ── Common ports with known service names ─────
COMMON_PORTS = {
    21:"ftp", 22:"ssh", 23:"telnet", 25:"smtp", 53:"dns",
    67:"dhcp", 68:"dhcp", 69:"tftp", 80:"http", 88:"kerberos",
    110:"pop3", 111:"rpcbind", 119:"nntp", 123:"ntp", 135:"msrpc",
    137:"netbios-ns", 138:"netbios-dgm", 139:"netbios-ssn",
    143:"imap", 161:"snmp", 162:"snmptrap", 179:"bgp",
    389:"ldap", 443:"https", 445:"smb", 465:"smtps",
    500:"isakmp", 502:"modbus", 514:"syslog", 515:"lpd",
    521:"ripng", 554:"rtsp", 587:"smtp-sub", 593:"http-rpc",
    623:"ipmi", 631:"ipp", 636:"ldaps", 873:"rsync",
    902:"vmware", 993:"imaps", 995:"pop3s", 1080:"socks",
    1194:"openvpn", 1433:"mssql", 1434:"mssql-udp",
    1521:"oracle", 1723:"pptp", 1883:"mqtt", 2049:"nfs",
    2121:"ftp-alt", 2181:"zookeeper", 2222:"ssh-alt",
    2375:"docker", 2376:"docker-tls", 2379:"etcd",
    3000:"grafana", 3306:"mysql", 3389:"rdp", 3690:"svn",
    4369:"epmd", 4444:"metasploit", 4848:"glassfish",
    5000:"flask", 5432:"postgresql", 5555:"adb",
    5601:"kibana", 5672:"amqp", 5900:"vnc", 5985:"winrm",
    5986:"winrm-tls", 6379:"redis", 6443:"k8s-api",
    7001:"weblogic", 7077:"spark", 7474:"neo4j",
    8000:"http-alt", 8080:"http-proxy", 8081:"http-alt2",
    8086:"influxdb", 8088:"http-alt3", 8161:"activemq",
    8443:"https-alt", 8500:"consul", 8888:"jupyter",
    9000:"sonarqube", 9042:"cassandra", 9090:"prometheus",
    9092:"kafka", 9200:"elasticsearch", 9300:"es-transport",
    9418:"git", 10250:"kubelet", 11211:"memcached",
    15672:"rabbitmq-mgmt", 27017:"mongodb", 27018:"mongodb-shard",
    50000:"db2", 50070:"hadoop-hdfs", 50030:"hadoop-mr",
    61616:"activemq-openwire",
}

# ── Banner / service probe payloads (inspired by nmap service-probes) ─
SERVICE_PROBES = {
    "http":     b"GET / HTTP/1.0\r\nHost: target\r\n\r\n",
    "https":    b"GET / HTTP/1.0\r\nHost: target\r\n\r\n",
    "ftp":      b"",          # wait for banner
    "ssh":      b"",          # wait for banner
    "smtp":     b"EHLO discoveryking\r\n",
    "pop3":     b"",          # wait for banner
    "imap":     b"A001 CAPABILITY\r\n",
    "telnet":   b"",          # wait for banner
    "mysql":    b"\x00",      # trigger handshake
    "redis":    b"*1\r\n$4\r\nPING\r\n",
    "mongodb":  b"\x41\x00\x00\x00\x3a\x30\x00\x00\xff\xff\xff\xff\xd4\x07\x00\x00\x00\x00\x00\x00test.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff\x1b\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00",
    "smb":      b"\x00\x00\x00\xa4\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x08\x01\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x06\x00\x00\x01\x00\x00\x81\x00\x02NT LM 0.12\x00",
    "rdp":      b"\x03\x00\x00\x2a\x25\xe0\x00\x00\x00\x00\x00Cookie: mstshash=nmap\r\n\x01\x00\x08\x00\x03\x00\x00\x00",
    "dns":      b"\x00\x1e\x00\x06\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
    "generic":  b"\r\n",
}

# ── Version / service fingerprint patterns ────
VERSION_PATTERNS = [
    # SSH
    (re.compile(rb"SSH-([\d.]+)-([^\r\n]+)"),
     lambda m: (f"SSH", f"{m.group(2).decode(errors='ignore').strip()}", f"protocol {m.group(1).decode()}")),
    # HTTP Server header
    (re.compile(rb"[Ss]erver:\s*([^\r\n]+)"),
     lambda m: ("HTTP", m.group(1).decode(errors='ignore').strip(), "")),
    # FTP
    (re.compile(rb"220[- ]([^\r\n]+)"),
     lambda m: ("FTP", m.group(1).decode(errors='ignore').strip(), "")),
    # SMTP
    (re.compile(rb"220[- ]([^\r\n]+)SMTP([^\r\n]*)"),
     lambda m: ("SMTP", m.group(1).decode(errors='ignore').strip(), "")),
    # POP3
    (re.compile(rb"\+OK ([^\r\n]+)"),
     lambda m: ("POP3", m.group(1).decode(errors='ignore').strip(), "")),
    # IMAP
    (re.compile(rb"\* OK ([^\r\n]+)"),
     lambda m: ("IMAP", m.group(1).decode(errors='ignore').strip(), "")),
    # Redis
    (re.compile(rb"\+PONG|\$\d+\r\nredis_version:([^\r\n]+)"),
     lambda m: ("Redis", m.group(1).decode(errors='ignore').strip() if m.lastindex else "Redis", "")),
    # MySQL
    (re.compile(rb"[\x00-\xff]{4}[\x0a]([\d.]+)\x00"),
     lambda m: ("MySQL", m.group(1).decode(errors='ignore'), "")),
    # MongoDB
    (re.compile(rb"ismaster|isMaster|MongoDB"),
     lambda m: ("MongoDB", "MongoDB", "")),
    # RDP
    (re.compile(rb"\x03\x00\x00"),
     lambda m: ("RDP", "Microsoft Remote Desktop", "")),
    # SMB
    (re.compile(rb"\xffSMB|\xfeSMB"),
     lambda m: ("SMB", "Samba / Windows File Sharing", "")),
    # Telnet
    (re.compile(rb"\xff[\xfb-\xfe]."),
     lambda m: ("Telnet", "Telnet Service", "")),
    # Generic version strings
    (re.compile(rb"([A-Za-z][\w/ .-]{1,20})[\s/v]+([\d][.\d]{1,8})"),
     lambda m: (m.group(1).decode(errors='ignore').strip(),
                m.group(2).decode(errors='ignore').strip(), "")),
]

# ── SSL/TLS cert grabber ──────────────────────
def grab_ssl_info(host, port, timeout=4):
    """Try TLS handshake and return cert subject info."""
    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                cert = s.getpeercert(binary_form=False)
                cipher = s.cipher()
                info = {}
                if cert:
                    subj = dict(x[0] for x in cert.get("subject", []))
                    info["cn"]      = subj.get("commonName", "")
                    info["org"]     = subj.get("organizationName", "")
                    info["expires"] = cert.get("notAfter", "")
                if cipher:
                    info["cipher"]  = f"{cipher[0]} / {cipher[1]}"
                return info
    except Exception:
        return {}

# ── Banner grabber ────────────────────────────
def grab_banner(host, port, timeout=4, probe_key="generic"):
    """
    Connect to host:port, send a probe, return raw banner bytes.
    Tries up to 2 probes: service-specific then generic fallback.
    """
    probe = SERVICE_PROBES.get(probe_key, SERVICE_PROBES["generic"])
    for p in [probe, SERVICE_PROBES["generic"]]:
        try:
            with socket.create_connection((host, port), timeout=timeout) as s:
                s.settimeout(timeout)
                if p:
                    s.sendall(p)
                banner = b""
                try:
                    while True:
                        chunk = s.recv(2048)
                        if not chunk:
                            break
                        banner += chunk
                        if len(banner) > 4096:
                            break
                except socket.timeout:
                    pass
                if banner:
                    return banner
        except Exception:
            pass
    return b""

# ── Service fingerprinter ─────────────────────
def fingerprint_service(banner: bytes, port: int):
    """
    Match banner against VERSION_PATTERNS.
    Returns (service_name, version, extra_info).
    """
    if not banner:
        return COMMON_PORTS.get(port, "unknown"), "", ""
    for pattern, extractor in VERSION_PATTERNS:
        m = pattern.search(banner)
        if m:
            try:
                svc, ver, extra = extractor(m)
                return svc, ver, extra
            except Exception:
                continue
    # Fallback: printable snippet
    snippet = banner[:80].decode("utf-8", errors="replace").strip()
    snippet = re.sub(r"[\x00-\x1f\x7f-\x9f]+", " ", snippet)[:60]
    return COMMON_PORTS.get(port, "unknown"), "", snippet

# ── TCP Connect scan ──────────────────────────
def tcp_connect_scan(host, port, timeout=2):
    """Standard TCP connect — most reliable, works without root."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

# ── SYN scan (raw socket, requires root) ──────
def tcp_syn_scan(host, port, timeout=2):
    """
    Half-open SYN scan: sends SYN, listens for SYN-ACK (open)
    or RST (closed). Falls back to connect scan if not root.
    Advanced: lower detection footprint than full connect.
    """
    try:
        import struct
        def checksum(data):
            if len(data) % 2:
                data += b'\x00'
            s = 0
            for i in range(0, len(data), 2):
                s += (data[i] << 8) + data[i+1]
            s = (s >> 16) + (s & 0xffff)
            s += (s >> 16)
            return ~s & 0xffff

        src_ip  = socket.gethostbyname(socket.gethostname())
        dst_ip  = socket.gethostbyname(host)
        src_port= random.randint(1024, 65535)

        # IP header
        ip_ihl_ver  = (4 << 4) | 5
        ip_tos      = 0; ip_tot_len = 0; ip_id = random.randint(1,65535)
        ip_frag_off = 0; ip_ttl = 64; ip_proto = socket.IPPROTO_TCP
        ip_check    = 0
        ip_saddr    = socket.inet_aton(src_ip)
        ip_daddr    = socket.inet_aton(dst_ip)
        ip_header   = struct.pack("!BBHHHBBH4s4s",
                        ip_ihl_ver, ip_tos, ip_tot_len, ip_id,
                        ip_frag_off, ip_ttl, ip_proto, ip_check,
                        ip_saddr, ip_daddr)

        # TCP header (SYN flag = 0x002)
        tcp_seq   = random.randint(0, 2**32-1)
        tcp_flags = 0x002  # SYN
        tcp_window= socket.htons(65535)
        tcp_header= struct.pack("!HHLLBBHHH",
                        src_port, port, tcp_seq, 0,
                        5<<4, tcp_flags, tcp_window, 0, 0)

        # Pseudo header for checksum
        pseudo = struct.pack("!4s4sBBH",
                    ip_saddr, ip_daddr, 0,
                    socket.IPPROTO_TCP, len(tcp_header))
        tcp_cksum = checksum(pseudo + tcp_header)
        tcp_header= struct.pack("!HHLLBBHHH",
                        src_port, port, tcp_seq, 0,
                        5<<4, tcp_flags, tcp_window, tcp_cksum, 0)

        raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        raw.settimeout(timeout)
        raw.sendto(ip_header + tcp_header, (dst_ip, 0))

        end = time.time() + timeout
        while time.time() < end:
            try:
                pkt = raw.recv(4096)
                ip_hlen = (pkt[0] & 0x0f) * 4
                tcp_pkt = pkt[ip_hlen:]
                if len(tcp_pkt) < 14:
                    continue
                flags = tcp_pkt[13]
                r_port = struct.unpack("!H", tcp_pkt[0:2])[0]
                if r_port == port:
                    if flags & 0x12 == 0x12:   # SYN-ACK → open
                        raw.close(); return True
                    elif flags & 0x04:          # RST → closed
                        raw.close(); return False
            except socket.timeout:
                break
        raw.close()
    except PermissionError:
        pass  # fall through to connect scan
    except Exception:
        pass
    return tcp_connect_scan(host, port, timeout)

# ── UDP scan (requires root for raw, else heuristic) ─
def udp_scan(host, port, timeout=3):
    """
    Send empty UDP datagram; ICMP port-unreachable → closed.
    No response → likely open|filtered (common for UDP).
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(b"\x00" * 4, (host, port))
        try:
            s.recv(1024)
            s.close(); return "open"
        except socket.timeout:
            s.close(); return "open|filtered"
        except ConnectionRefusedError:
            s.close(); return "closed"
    except Exception:
        return "unknown"

# ── OS fingerprint (TTL + window size heuristic) ─
def os_fingerprint_ttl(host):
    """
    Ping and parse TTL from response.
    TTL 64  → Linux/macOS/FreeBSD
    TTL 128 → Windows
    TTL 255 → Network device / Cisco
    Advanced: also checks open port TCP window size if available.
    """
    param = "-n" if platform.system().lower() == "windows" else "-c"
    try:
        result = subprocess.run(
            ["ping", param, "1", host],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5
        )
        out = result.stdout.decode(errors="ignore")
        # Parse TTL
        m = re.search(r"ttl[=:](\d+)", out, re.IGNORECASE)
        if not m:
            return "unknown"
        ttl = int(m.group(1))
        if ttl <= 64:
            return f"Linux/macOS/FreeBSD  {C.DIM}(TTL={ttl}){C.RESET}"
        elif ttl <= 128:
            return f"Windows              {C.DIM}(TTL={ttl}){C.RESET}"
        elif ttl <= 255:
            return f"Network device/Cisco {C.DIM}(TTL={ttl}){C.RESET}"
        return f"Unknown OS           {C.DIM}(TTL={ttl}){C.RESET}"
    except Exception:
        return "unknown"

# ── Port scan output formatter ────────────────
def format_port_result(port, state, service, version, extra, ssl_info):
    state_color = C.GREEN if state == "open" else C.YELLOW
    port_col    = f"{C.BOLD}{C.CYAN}{port:<6}{C.RESET}"
    state_col   = f"{state_color}{state:<16}{C.RESET}"
    svc_col     = f"{C.LIME}{service:<18}{C.RESET}"
    ver_col     = f"{C.WHITE}{version}{C.RESET}" if version else ""
    extra_col   = f"{C.DIM} [{extra}]{C.RESET}" if extra else ""
    ssl_col     = ""
    if ssl_info:
        parts = []
        if ssl_info.get("cn"):    parts.append(f"CN={ssl_info['cn']}")
        if ssl_info.get("cipher"):parts.append(ssl_info['cipher'])
        if ssl_info.get("expires"):parts.append(f"exp:{ssl_info['expires']}")
        ssl_col = f"  {C.TEAL}[TLS: {', '.join(parts)}]{C.RESET}"
    with _print_lock:
        print(f"  {port_col} {state_col} {svc_col} {ver_col}{extra_col}{ssl_col}")

# ── Main port scanner ─────────────────────────
def scan_ports(host, ports=None, scan_type="connect",
               threads_limit=100, timeout=2, stealth=False, udp=False):
    """
    Full port scan engine with:
    - TCP Connect scan (default, no root needed)
    - SYN scan (half-open, root only, lower footprint)
    - UDP scan (optional, root preferred)
    - Banner grabbing + service fingerprinting
    - SSL/TLS cert extraction
    - OS fingerprinting via TTL
    - Multithreaded (up to threads_limit concurrent)
    """
    if ports is None:
        ports = list(COMMON_PORTS.keys())

    print_section(f"  PORT SCAN  [{host}]  {len(ports)} ports  [{scan_type.upper()}]  ", C.GOLD)

    # OS fingerprint first
    log_info(f"OS fingerprint: {os_fingerprint_ttl(host)}")

    # Header
    with _print_lock:
        print(f"\n  {C.BOLD}{C.DIM}{'PORT':<6} {'STATE':<16} {'SERVICE':<18} VERSION{C.RESET}")
        print(f"  {C.DIM}{'─'*70}{C.RESET}")

    open_count  = 0
    result_lock = threading.Lock()
    semaphore   = threading.Semaphore(threads_limit)

    def probe_port(port):
        nonlocal open_count

        if stealth:
            time.sleep(random.uniform(0.05, 0.3))

        # ── TCP ────────────────────────────────
        if scan_type == "syn":
            is_open = tcp_syn_scan(host, port, timeout)
        else:
            is_open = tcp_connect_scan(host, port, timeout)

        if is_open:
            # Probe name
            probe_key = COMMON_PORTS.get(port, "generic")
            if port in (443, 8443, 993, 995, 465, 636, 8883):
                probe_key = "https"

            # Banner + fingerprint
            banner  = grab_banner(host, port, timeout, probe_key)
            service, version, extra = fingerprint_service(banner, port)

            # SSL info for likely TLS ports
            ssl_info = {}
            if port in (443, 8443, 465, 993, 995, 636, 8883, 5986, 2376, 6443) or "https" in probe_key:
                ssl_info = grab_ssl_info(host, port, timeout)

            with result_lock:
                open_count += 1
                with STATS.lock:
                    STATS.open_ports += 1
            format_port_result(port, "open", service, version, extra, ssl_info)

        # ── UDP (optional) ─────────────────────
        if udp and port in (53, 67, 68, 69, 123, 161, 500, 514, 623, 1194, 1434, 4500, 5353):
            state = udp_scan(host, port, timeout)
            if "open" in state:
                probe_key = COMMON_PORTS.get(port, "generic")
                banner    = b""
                service   = COMMON_PORTS.get(port, "udp-service")
                with result_lock:
                    open_count += 1
                format_port_result(port, f"udp/{state}", service, "", "", {})

    threads = []
    for port in sorted(ports):
        def worker(p=port):
            with semaphore:
                probe_port(p)
        t = threading.Thread(target=worker, daemon=True)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    with _print_lock:
        print(f"\n  {C.DIM}{'─'*70}{C.RESET}")
        if open_count:
            log_ok(f"{C.LIME}{C.BOLD}{open_count}{C.RESET} open port(s) found on {C.CYAN}{host}{C.RESET}")
        else:
            log_warn(f"No open ports found on {host} (scanned {len(ports)} ports)")

# ── Port range parser ─────────────────────────
def parse_ports(port_str):
    """
    Parse port spec:
      22              → [22]
      22,80,443       → [22,80,443]
      1-1024          → [1..1024]
      top100          → top 100 most common ports
      top1000         → top 1000 most common ports
      all             → 1-65535
    """
    port_str = port_str.strip().lower()
    if port_str == "top100":
        return list(COMMON_PORTS.keys())[:100]
    if port_str == "top1000":
        extra = list(range(1, 1024)) + list(COMMON_PORTS.keys())
        return sorted(set(extra))[:1000]
    if port_str == "all":
        return list(range(1, 65536))
    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b)+1))
        else:
            ports.add(int(part))
    return sorted(ports)

# ─────────────────────────────────────────────
#  ADAPTIVE REQUEST ENGINE
# ─────────────────────────────────────────────
class AdaptiveRequestEngine:
    def __init__(self, stealth=False, max_retries=3):
        self.stealth = stealth
        self.max_retries = max_retries
        self.ua_index = 0
        self.request_delay = 0.5 if not stealth else random.uniform(1.5, 3.0)
        self.rate_limited_until = 0

    def _base_headers(self):
        ua = USER_AGENTS[self.ua_index % len(USER_AGENTS)]
        return {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "max-age=0",
        }

    def _evasion_headers(self, attempt=1):
        """Build progressively more 'legit-looking' headers."""
        headers = self._base_headers()
        if attempt >= 2:
            fake_ip = random.choice(DECOY_IPS)
            headers.update({
                "X-Forwarded-For": fake_ip,
                "X-Originating-IP": fake_ip,
                "X-Remote-IP": fake_ip,
                "X-Remote-Addr": fake_ip,
                "True-Client-IP": fake_ip,
                "Client-IP": fake_ip,
            })
        if attempt >= 3:
            headers.update({
                "Referer": "https://www.google.com/",
                "Origin": "https://www.google.com",
                "DNT": "1",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "cross-site",
                "Sec-Fetch-User": "?1",
                "Pragma": "no-cache",
            })
        return headers

    def rotate_ua(self):
        self.ua_index = (self.ua_index + 1) % len(USER_AGENTS)

    def apply_evasion_strategy(self, attempt, target):
        """Determine and log strategy for retry attempt."""
        self.rotate_ua()
        ua_short = USER_AGENTS[self.ua_index % len(USER_AGENTS)][:55] + "..."
        log_retry(f"Retrying (attempt {attempt}) with new UA: {C.DIM}{ua_short}{C.RESET}")

        if attempt == 2:
            log_warn("Adding X-Forwarded-For + IP spoof headers")
        if attempt == 3:
            log_warn("Adding Referer, Origin, Sec-Fetch headers")

        delay = random.uniform(1.0, 5.0) if self.stealth else random.uniform(0.3, 1.5)
        log_retry(f"Delay: {C.GOLD}{delay:.2f}s{C.RESET}")
        time.sleep(delay)

    def fetch(self, url, method="GET"):
        """
        Attempt an HTTP fetch with adaptive evasion on blocking.
        Returns (status_code, headers_dict, body_snippet).
        """
        # Rate-limit cooldown
        now = time.time()
        if now < self.rate_limited_until:
            wait = self.rate_limited_until - now
            log_rate(f"Rate limit cooldown — waiting {wait:.1f}s")
            time.sleep(wait)

        for attempt in range(1, self.max_retries + 1):
            headers = self._evasion_headers(attempt)
            try:
                schemes = ["https", "http"] if "https" in url else ["http", "https"]
                parsed = urlparse(url)
                base_url = url

                for scheme in schemes:
                    try_url = scheme + "://" + parsed.netloc + parsed.path
                    req = Request(try_url, headers=headers, method=method)
                    try:
                        with urlopen(req, timeout=8) as resp:
                            status = resp.status
                            resp_headers = dict(resp.headers)
                            body = resp.read(2048).decode("utf-8", errors="ignore")

                            wafs = detect_waf(resp_headers, body, status)
                            if wafs:
                                with STATS.lock:
                                    STATS.waf_detected += 1
                                for (name, wc) in wafs:
                                    log_detect(f"WAF/CDN Detected: {wc}{C.BOLD}{name}{C.RESET}")

                            if status == 429:
                                with STATS.lock:
                                    STATS.rate_limited += 1
                                self.rate_limited_until = time.time() + random.uniform(10, 20)
                                log_rate("Rate limit detected — slowing down...")
                                time.sleep(random.uniform(5, 10))
                                break

                            if is_blocking_response(status, body):
                                log_warn(f"Blocking response [{status}] on {try_url}")
                                if attempt < self.max_retries:
                                    self.apply_evasion_strategy(attempt + 1, url)
                                    with STATS.lock:
                                        STATS.retried += 1
                                break
                            else:
                                return status, resp_headers, body

                    except HTTPError as e:
                        wafs = detect_waf(dict(e.headers), "", e.code)
                        if wafs:
                            for (name, wc) in wafs:
                                log_detect(f"WAF/CDN Detected: {wc}{C.BOLD}{name}{C.RESET}")
                        if e.code == 429:
                            with STATS.lock:
                                STATS.rate_limited += 1
                            self.rate_limited_until = time.time() + random.uniform(10, 20)
                            log_rate("Rate limit detected — slowing down...")
                            time.sleep(random.uniform(5, 10))
                        if is_blocking_response(e.code):
                            log_warn(f"HTTP {e.code} on {try_url}")
                            if attempt < self.max_retries:
                                self.apply_evasion_strategy(attempt + 1, url)
                                with STATS.lock:
                                    STATS.retried += 1
                        return e.code, dict(e.headers), ""

                    except URLError as e:
                        log_error(f"URL Error on {try_url}: {e.reason}")

            except Exception as e:
                log_error(f"Fetch exception: {e}")

        return None, {}, ""


# ─────────────────────────────────────────────
#  HOST SCANNER (ICMP PING)
# ─────────────────────────────────────────────
def ping_host(ip, stealth=False):
    param = "-n" if platform.system().lower() == "windows" else "-c"

    if stealth:
        delay = random.uniform(0.2, 1.5)
        time.sleep(delay)

    start_time = time.time()
    result = subprocess.run(
        ["ping", param, "1", str(ip)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    end_time = time.time()

    if result.returncode == 0:
        ms = round((end_time - start_time) * 1000, 2)
        bar = make_latency_bar(ms)
        log_host(ip, f"{C.GREEN}REACHABLE{C.RESET}  {bar}  {C.LIME}{ms}ms{C.RESET}", C.GREEN)
        with STATS.lock:
            STATS.reachable += 1
    else:
        with STATS.lock:
            STATS.unreachable += 1


def make_latency_bar(ms):
    """Render a tiny colored bar showing latency."""
    bars = int(min(ms, 500) / 50)
    color = C.GREEN if ms < 100 else C.YELLOW if ms < 300 else C.RED
    return f"{color}{'█' * bars}{'░' * (10 - bars)}{C.RESET}"


def ping_ip_range(start_ip, end_ip, stealth=False, threads_limit=50):
    start = ipaddress.IPv4Address(start_ip)
    end   = ipaddress.IPv4Address(end_ip)

    total = int(end) - int(start) + 1
    print_section(f"  ICMP PING SWEEP  [{start_ip} → {end_ip}]  {total} hosts  ", C.CYAN)

    if stealth:
        log_stealth("Stealth mode: randomized delays, limited concurrency")
        threads_limit = min(threads_limit, 10)

    semaphore = threading.Semaphore(threads_limit)
    threads = []

    for ip_int in range(int(start), int(end) + 1):
        ip = ipaddress.IPv4Address(ip_int)

        def worker(ip=ip):
            with semaphore:
                ping_host(ip, stealth)

        t = threading.Thread(target=worker)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()


# ─────────────────────────────────────────────
#  DNS RESOLUTION
# ─────────────────────────────────────────────
def resolve_host(host):
    try:
        ip = socket.gethostbyname(host)
        log_ok(f"DNS resolved: {C.CYAN}{host}{C.RESET} → {C.LIME}{ip}{C.RESET}")
        return ip
    except socket.gaierror as e:
        log_error(f"DNS resolution failed for {host}: {e}")
        return None


# ─────────────────────────────────────────────
#  HTTP HOST PROBE
# ─────────────────────────────────────────────
def probe_host(target, engine: AdaptiveRequestEngine):
    """Full HTTP probe with WAF detection on a hostname/URL."""
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    log_info(f"Scanning {C.CYAN}{target}{C.RESET}")

    status, headers, body = engine.fetch(target)

    if status is None:
        log_error(f"All attempts failed for {target}")
        return

    status_color = C.GREEN if status < 300 else C.YELLOW if status < 400 else C.RED
    log_ok(f"Response: {status_color}{C.BOLD}{status}{C.RESET}  Server: {C.DIM}{headers.get('Server', 'unknown')}{C.RESET}")

    # Show interesting response headers
    interesting = ["content-type", "x-powered-by", "via", "x-cache", "strict-transport-security"]
    for h in interesting:
        val = headers.get(h, headers.get(h.title(), ""))
        if val:
            log_info(f"  {C.DIM}{h}:{C.RESET} {val}")


# ─────────────────────────────────────────────
#  RESULTS SUMMARY
# ─────────────────────────────────────────────
def print_summary():
    print_section("  SCAN SUMMARY  ", C.PURPLE)
    elapsed = STATS.elapsed()

    rows = [
        ("Reachable hosts",  str(STATS.reachable),    C.GREEN),
        ("Unreachable hosts",str(STATS.unreachable),   C.RED),
        ("Open ports found", str(STATS.open_ports),    C.LIME),
        ("WAF detections",   str(STATS.waf_detected),  C.ORANGE),
        ("Rate limits hit",  str(STATS.rate_limited),  C.YELLOW),
        ("Retried requests", str(STATS.retried),       C.MAGENTA),
        ("Elapsed time",     f"{elapsed}s",            C.CYAN),
    ]

    for label, val, color in rows:
        with _print_lock:
            print(f"  {C.DIM}{'·' * 3}  {C.WHITE}{label:<22}{C.RESET}{color}{C.BOLD}{val}{C.RESET}")

    print_separator()
    with _print_lock:
        print(f"\n  {C.DIM}Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{C.RESET}\n")


# ─────────────────────────────────────────────
#  IP INPUT PARSER  (single / range / CIDR)
# ─────────────────────────────────────────────
def parse_ip_input(ip_arg):
    """
    Accepts:
      192.168.1.1            single host
      192.168.1.1-50         short range (last octet)
      192.168.1.1-192.168.1.254  full range
      192.168.1.0/24         CIDR
    Returns (start_ip_str, end_ip_str).
    """
    ip_arg = ip_arg.strip()

    # CIDR  e.g. 192.168.1.0/24
    if "/" in ip_arg:
        try:
            net   = ipaddress.IPv4Network(ip_arg, strict=False)
            hosts = list(net.hosts())
            if not hosts:                          # /32 single host
                return str(net.network_address), str(net.network_address)
            return str(hosts[0]), str(hosts[-1])
        except ValueError as e:
            log_error(f"Invalid CIDR '{ip_arg}': {e}")
            sys.exit(1)

    # Range with dash  e.g. 192.168.1.1-50  OR  192.168.1.1-192.168.1.254
    if "-" in ip_arg:
        start, end_part = ip_arg.split("-", 1)
        start    = start.strip()
        end_part = end_part.strip()
        end      = end_part if "." in end_part else ".".join(start.split(".")[:3]) + "." + end_part
        try:
            ipaddress.IPv4Address(start)
            ipaddress.IPv4Address(end)
            return start, end
        except ValueError as e:
            log_error(f"Invalid IP range '{ip_arg}': {e}")
            sys.exit(1)

    # Single IP
    try:
        ipaddress.IPv4Address(ip_arg)
        return ip_arg, ip_arg
    except ValueError as e:
        log_error(f"Invalid IP '{ip_arg}': {e}")
        sys.exit(1)


# ─────────────────────────────────────────────
#  ARGUMENT PARSER
# ─────────────────────────────────────────────
def build_parser():
    parser = argparse.ArgumentParser(
        prog="discoveryking",
        description=f"{C.CYAN}DiscoveryKing — Host Discovery + WAF/CDN Detection + Port Scanner  |  by l33tkid{C.RESET}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{C.DIM}Examples:
  # Ping sweep
  python discoveryking.py -ip 192.168.1.0/24
  python discoveryking.py -ip 192.168.1.1-50

  # Port scan with default common ports
  python discoveryking.py -ip 192.168.1.1 -p

  # Port scan specific ports
  python discoveryking.py -ip 192.168.1.1 -p -ports 22,80,443,3306

  # Port scan a range
  python discoveryking.py -ip 192.168.1.1 -p -ports 1-1024

  # Top 1000 ports + UDP
  python discoveryking.py -ip 192.168.1.1 -p -ports top1000 --udp

  # SYN scan (requires root/admin)
  sudo python discoveryking.py -ip 192.168.1.1 -p --syn

  # All in one: ping + port scan + WAF probe
  python discoveryking.py -ip 192.168.1.0/24 -p -url example.com

  # Stealth mode
  python discoveryking.py -ip 192.168.1.1 -p --stealth

  # Web target probe
  python discoveryking.py -url example.com

  # File input
  python discoveryking.py -f hosts.txt{C.RESET}
        """
    )
    parser.add_argument("-ip",       metavar="IP/RANGE/CIDR",
                        help="Single IP, range (1.1.1.1-50), or CIDR (1.1.1.0/24)")
    parser.add_argument("-url",      metavar="URL",
                        help="Web target to probe  e.g. example.com")
    parser.add_argument("-f",        metavar="FILE",
                        help="File with IPs or URLs, one per line")
    parser.add_argument("-p",        action="store_true",
                        help="Enable port scanning")
    parser.add_argument("-ports",    metavar="PORTS", default=None,
                        help="Ports: 22,80,443 | 1-1024 | top100 | top1000 | all  (default: common)")
    parser.add_argument("--syn",     action="store_true",
                        help="SYN scan / half-open scan (requires root)")
    parser.add_argument("--udp",     action="store_true",
                        help="Also scan common UDP ports")
    parser.add_argument("--stealth", action="store_true",
                        help="Slow + randomized stealth mode")
    parser.add_argument("--retries", type=int, default=3, metavar="N",
                        help="Retry attempts on HTTP block (default: 3)")
    parser.add_argument("--threads", type=int, default=100, metavar="N",
                        help="Max concurrent threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=2.0, metavar="S",
                        help="Socket timeout in seconds (default: 2.0)")
    parser.add_argument("--no-banner", action="store_true",
                        help="Skip the ASCII banner")
    return parser


# ─────────────────────────────────────────────
#  INTERACTIVE MODE (no args)
# ─────────────────────────────────────────────
def interactive_mode():
    print(f"\n{C.CYAN}╔══════════════════════════╗{C.RESET}")
    print(f"{C.CYAN}║{C.RESET}  1. ICMP Ping Sweep       {C.CYAN}║{C.RESET}")
    print(f"{C.CYAN}║{C.RESET}  2. Port Scan             {C.CYAN}║{C.RESET}")
    print(f"{C.CYAN}║{C.RESET}  3. HTTP / WAF Probe      {C.CYAN}║{C.RESET}")
    print(f"{C.CYAN}║{C.RESET}  4. Full Recon (all)      {C.CYAN}║{C.RESET}")
    print(f"{C.CYAN}╚══════════════════════════╝{C.RESET}")

    choice  = input(f"\n{C.BOLD}Select mode [1/2/3/4]: {C.RESET}").strip()
    stealth = input(f"{C.BOLD}Enable stealth mode? [y/N]: {C.RESET}").strip().lower() == "y"
    engine  = AdaptiveRequestEngine(stealth=stealth)

    if stealth:
        log_stealth("Stealth mode ENABLED — slow + randomized requests")

    if choice in ("1", "4"):
        raw = input(f"{C.BOLD}IP / Range / CIDR  (e.g. 192.168.1.0/24): {C.RESET}").strip()
        s, e = parse_ip_input(raw)
        ping_ip_range(s, e, stealth=stealth)

    if choice in ("2", "4"):
        raw = input(f"{C.BOLD}Target IP (single): {C.RESET}").strip()
        ps  = input(f"{C.BOLD}Ports [Enter=common | 1-1024 | top1000 | all]: {C.RESET}").strip()
        ports = parse_ports(ps) if ps else list(COMMON_PORTS.keys())
        stype = "syn" if input(f"{C.BOLD}SYN scan? (needs root) [y/N]: {C.RESET}").strip().lower()=="y" else "connect"
        udp_on= input(f"{C.BOLD}UDP scan common ports? [y/N]: {C.RESET}").strip().lower() == "y"
        scan_ports(raw, ports, scan_type=stype, stealth=stealth, udp=udp_on)

    if choice in ("3", "4"):
        target = input(f"{C.BOLD}URL or host  (e.g. example.com): {C.RESET}").strip()
        probe_host(target, engine)


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────
def main():
    parser = build_parser()
    args   = parser.parse_args()

    if not args.no_banner:
        print(BANNER)

    engine = AdaptiveRequestEngine(stealth=args.stealth, max_retries=args.retries)

    if args.stealth:
        log_stealth("Stealth mode ENABLED — slow, randomized, low-noise scan")

    # Determine scan type
    scan_type = "syn" if args.syn else "connect"
    if args.syn:
        log_warn("SYN scan mode — requires root/admin privileges")

    # Determine port list
    if args.ports:
        port_list = parse_ports(args.ports)
    else:
        port_list = list(COMMON_PORTS.keys())

    no_args = not args.ip and not args.url and not args.f
    if no_args:
        interactive_mode()
        print_summary()
        return

    # ── -ip ───────────────────────────────────
    if args.ip:
        start_ip, end_ip = parse_ip_input(args.ip)

        # Ping sweep
        ping_ip_range(start_ip, end_ip,
                      stealth=args.stealth, threads_limit=args.threads)

        # Port scan — only if -p given; scan each discovered host
        if args.p:
            # If single host, scan it directly
            if start_ip == end_ip:
                scan_ports(start_ip, port_list,
                           scan_type=scan_type,
                           threads_limit=args.threads,
                           timeout=args.timeout,
                           stealth=args.stealth,
                           udp=args.udp)
            else:
                # For ranges: user must target specific IPs with -ip single + -p
                # or we scan the whole range (can be slow — warn first)
                total = int(ipaddress.IPv4Address(end_ip)) - int(ipaddress.IPv4Address(start_ip)) + 1
                log_warn(f"Port scanning {total} hosts × {len(port_list)} ports — this may take a while")
                for ip_int in range(int(ipaddress.IPv4Address(start_ip)),
                                    int(ipaddress.IPv4Address(end_ip)) + 1):
                    ip = str(ipaddress.IPv4Address(ip_int))
                    scan_ports(ip, port_list,
                               scan_type=scan_type,
                               threads_limit=args.threads,
                               timeout=args.timeout,
                               stealth=args.stealth,
                               udp=args.udp)

    # ── -url ──────────────────────────────────
    if args.url:
        print_section(f"  HTTP PROBE  [{args.url}]  ", C.MAGENTA)
        probe_host(args.url, engine)
        # Also port scan the resolved IP if -p
        if args.p:
            resolved = resolve_host(args.url.replace("https://","").replace("http://","").split("/")[0])
            if resolved:
                scan_ports(resolved, port_list,
                           scan_type=scan_type,
                           threads_limit=args.threads,
                           timeout=args.timeout,
                           stealth=args.stealth,
                           udp=args.udp)

    # ── -f ────────────────────────────────────
    if args.f:
        try:
            with open(args.f) as fh:
                lines = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        except FileNotFoundError:
            log_error(f"File not found: {args.f}")
            sys.exit(1)

        ip_lines  = [l for l in lines if re.match(r"^\d{1,3}(\.\d{1,3}){1,3}", l)]
        url_lines = [l for l in lines if l not in ip_lines]

        if ip_lines:
            print_section(f"  IP SWEEP from file  [{len(ip_lines)} entries]  ", C.CYAN)
            for entry in ip_lines:
                s, e = parse_ip_input(entry)
                ping_ip_range(s, e, stealth=args.stealth, threads_limit=args.threads)
                if args.p and s == e:
                    scan_ports(s, port_list, scan_type=scan_type,
                               threads_limit=args.threads, timeout=args.timeout,
                               stealth=args.stealth, udp=args.udp)

        if url_lines:
            print_section(f"  HTTP PROBE from file  [{len(url_lines)} targets]  ", C.MAGENTA)
            for t in url_lines:
                probe_host(t, engine)
                if args.p:
                    host_only = t.replace("https://","").replace("http://","").split("/")[0]
                    resolved = resolve_host(host_only)
                    if resolved:
                        scan_ports(resolved, port_list, scan_type=scan_type,
                                   threads_limit=args.threads, timeout=args.timeout,
                                   stealth=args.stealth, udp=args.udp)
                time.sleep(engine.request_delay)

    print_summary()


if __name__ == "__main__":
    main()
