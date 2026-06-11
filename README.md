# SIEM Detection Lab — Wayne Enterprises Web Defacement Investigation

## Overview
This lab documents a hands-on security investigation using Splunk and the Boss of the SOC (BOTS) v1 dataset. I took on the role of a SOC analyst investigating a web defacement attack against Wayne Enterprises, tracing the attacker's steps from initial reconnaissance to site defacement.

**Tools Used:** Splunk, SPL (Search Processing Language)  
**Dataset:** Boss of the SOC (BOTS) v1 — hosted at bots.splunk.com  
**Attack Type:** Web defacement, vulnerability scanning, CMS exploitation  

---

## Data Sources
The following log sources were available for investigation:

| Sourcetype | Description |
|---|---|
| suricata | Network IDS — flags suspicious traffic patterns |
| stream:http | Raw HTTP traffic — every web request made to/from the server |
| fgt_utm | Fortinet firewall logs — traffic allowed or blocked at the perimeter |
| iis | Windows web server logs — every request the server received |
| stream:dns | DNS queries — domain name lookups made on the network |

---

## Attack Timeline
August 10, 2016
├── Attacker (40.80.148.42) runs Acunetix vulnerability scanner against imreallynotbatman.com
│   └── Thousands of automated HTTP requests probing for vulnerabilities
│
├── Scanner identifies site is running Joomla CMS
│
├── Attacker gains access to Joomla admin panel
│   └── Multiple POST requests to /joomla/administrator/index.php
│
└── Attacker uploads defacement image — poisonivy-is-coming-for-you-batman.jpeg
└── Site homepage replaced — defacement complete

---

## Investigation Findings

### Finding 1 — Attacker IP (Reconnaissance)
**Question:** What IP was scanning imreallynotbatman.com for vulnerabilities?

**SPL Query:**
index=botsv1 imreallynotbatman.com sourcetype=stream:http
| stats count by src_ip
| sort -count

**Methodology:** Vulnerability scanners send hundreds of automated requests in a short time. By counting HTTP requests per source IP and sorting highest first, the scanning IP stands out immediately due to its abnormally high request count.

**Finding:** `40.80.148.42` made significantly more requests than any other IP — consistent with automated vulnerability scanning.

**Answer:** 40.80.148.42

---

### Finding 2 — Scanning Tool Identification
**Question:** What company made the vulnerability scanner used by the attacker?

**SPL Query:**
index=botsv1 src_ip=40.80.148.42 sourcetype=stream:http
| stats count by http_user_agent
| sort -count

**Methodology:** Every tool that makes HTTP requests leaves a user agent string identifying itself. Vulnerability scanners often inject their own test strings into requests as fingerprints.

**Finding:** Multiple user agent strings contained `acunetix_wvs_security_test` — Acunetix's own security test signature left behind in HTTP requests.

**Answer:** Acunetix

---

### Finding 3 — CMS Identification
**Question:** What content management system is imreallynotbatman.com running?

**SPL Query:**
index=botsv1 imreallynotbatman.com sourcetype=stream:http
| stats count by uri_path
| sort -count

**Methodology:** CMS platforms have distinctive URL structures. By listing all URI paths requested on the site, the CMS reveals itself through its folder structure.

**Finding:** The majority of URI paths contained `/joomla/` — including `/joomla/index.php`, `/joomla/administrator/index.php`, and `/joomla/media/`. The site is running Joomla. Path traversal attempts against `/windows/win.ini` were also visible — the scanner probing for file inclusion vulnerabilities.

**Answer:** Joomla

---

### Finding 4 — Defacement File
**Question:** What file was used to deface the website?

**SPL Query:**
index=botsv1 "poisonivy-is-coming-for-you-batman.jpeg"

**Methodology:** Using threat intelligence — the attacker group name (Po1s0n1vy) and the target's Batman theme — to construct a targeted search. This is a common analyst technique: using known attacker TTPs and context to search more efficiently.

**Finding:** The filename `poisonivy-is-coming-for-you-batman.jpeg` was confirmed across multiple log sources — suricata, stream:http, and fgt_utm — confirming it was uploaded to and served from the web server.

**Answer:** poisonivy-is-coming-for-you-batman.jpeg

---

## Indicators of Compromise (IOCs)

| Type | Value | Description |
|---|---|---|
| IP Address | 40.80.148.42 | Attacker scanning IP |
| File | poisonivy-is-coming-for-you-batman.jpeg | Defacement image |
| Tool | Acunetix WVS | Vulnerability scanner used in recon |
| CMS | Joomla | Exploited CMS |
| URL | /joomla/administrator/index.php | Admin panel targeted |

---

## Key SPL Concepts Demonstrated
- `stats count by [field]` — grouping and counting events by field value
- `sort -count` — sorting results descending by count
- `table` — displaying specific fields only
- `dedup` — removing duplicate values
- Keyword search — searching for specific strings across all log sources
- Multi-sourcetype investigation — correlating findings across suricata, stream:http, and fgt_utm

---

## Certifications
- Splunk Intro to Splunk (eLearning) — June 2026
- Splunk Using Fields (eLearning) — June 2026
