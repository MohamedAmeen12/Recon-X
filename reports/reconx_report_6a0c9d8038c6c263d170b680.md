# ReconX Vulnerability Report

## Executive Summary
**Target:** vulnweb.com
**Generated At:** 2026-05-19 17:47:59 UTC
**Total Findings:** 16

## Findings Table
| ID | Title | Severity | Target | Endpoint/CVE |
| --- | --- | --- | --- | --- |
| RX-001 | Vulnerable Service: Web Service (CVE-2019-9020) | LOW | vulnweb.com | CVE-2019-9020 |
| RX-002 | Vulnerable Service: Web Service (CVE-2019-9021) | LOW | vulnweb.com | CVE-2019-9021 |
| RX-003 | Vulnerable Service: Web Service (CVE-2019-9023) | LOW | vulnweb.com | CVE-2019-9023 |
| RX-004 | Vulnerable Service: Web Service (CVE-2019-6977) | LOW | vulnweb.com | CVE-2019-6977 |
| RX-005 | Vulnerable Service: Web Service (CVE-2019-9022) | LOW | vulnweb.com | CVE-2019-9022 |
| RX-006 | Vulnerable Service: Web Service (CVE-2019-9024) | LOW | vulnweb.com | CVE-2019-9024 |
| RX-007 | Vulnerable Service: PHP (CVE-2019-6977) | HIGH | rest.vulnweb.com | CVE-2019-6977 |
| RX-008 | Vulnerable Service: PHP (CVE-2019-9020) | CRITICAL | rest.vulnweb.com | CVE-2019-9020 |
| RX-009 | Vulnerable Service: PHP (CVE-2019-9021) | CRITICAL | rest.vulnweb.com | CVE-2019-9021 |
| RX-010 | Vulnerable Service: PHP (CVE-2019-9022) | HIGH | rest.vulnweb.com | CVE-2019-9022 |
| RX-011 | Vulnerable Service: PHP (CVE-2019-9023) | CRITICAL | rest.vulnweb.com | CVE-2019-9023 |
| RX-012 | Vulnerable Service: PHP (CVE-2019-9024) | HIGH | rest.vulnweb.com | CVE-2019-9024 |
| RX-013 | HTTP Traffic Anomaly | MEDIUM | vulnweb.com | / |
| RX-014 | HTTP Traffic Anomaly | MEDIUM | www.vulnweb.com | / |
| RX-015 | HTTP Traffic Anomaly | MEDIUM | rest.vulnweb.com | / |
| RX-016 | HTTP Traffic Anomaly | MEDIUM | test.vulnweb.com | / |


## [Low] Vulnerable Service: Web Service (CVE-2019-9020)

**Target:**
vulnweb.com

**Endpoint:**
/

**Severity:**
Low

**CVE:**
CVE-2019-9020

**Description:**
A security vulnerability was identified on the service Web Service running on host vulnweb.com.

**Proof of Concept:**
```http
GET / HTTP/1.1
Host: vulnweb.com
User-Agent: ReconX-Agent
```

**Impact:**
An attacker could exploit this vulnerability to cause unauthorized access, service disruption, or configuration modification.

**Remediation:**
Update the Web Service component to the latest stable version and review service configurations.

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2019-9020


## [Low] Vulnerable Service: Web Service (CVE-2019-9021)

**Target:**
vulnweb.com

**Endpoint:**
/

**Severity:**
Low

**CVE:**
CVE-2019-9021

**Description:**
A security vulnerability was identified on the service Web Service running on host vulnweb.com.

**Proof of Concept:**
```http
GET / HTTP/1.1
Host: vulnweb.com
User-Agent: ReconX-Agent
```

**Impact:**
An attacker could exploit this vulnerability to cause unauthorized access, service disruption, or configuration modification.

**Remediation:**
Update the Web Service component to the latest stable version and review service configurations.

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2019-9021


## [Low] Vulnerable Service: Web Service (CVE-2019-9023)

**Target:**
vulnweb.com

**Endpoint:**
/

**Severity:**
Low

**CVE:**
CVE-2019-9023

**Description:**
A security vulnerability was identified on the service Web Service running on host vulnweb.com.

**Proof of Concept:**
```http
GET / HTTP/1.1
Host: vulnweb.com
User-Agent: ReconX-Agent
```

**Impact:**
An attacker could exploit this vulnerability to cause unauthorized access, service disruption, or configuration modification.

**Remediation:**
Update the Web Service component to the latest stable version and review service configurations.

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2019-9023


## [Low] Vulnerable Service: Web Service (CVE-2019-6977)

**Target:**
vulnweb.com

**Endpoint:**
/

**Severity:**
Low

**CVE:**
CVE-2019-6977

**Description:**
A security vulnerability was identified on the service Web Service running on host vulnweb.com.

**Proof of Concept:**
```http
GET / HTTP/1.1
Host: vulnweb.com
User-Agent: ReconX-Agent
```

**Impact:**
An attacker could exploit this vulnerability to cause unauthorized access, service disruption, or configuration modification.

**Remediation:**
Update the Web Service component to the latest stable version and review service configurations.

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2019-6977


## [Low] Vulnerable Service: Web Service (CVE-2019-9022)

**Target:**
vulnweb.com

**Endpoint:**
/

**Severity:**
Low

**CVE:**
CVE-2019-9022

**Description:**
A security vulnerability was identified on the service Web Service running on host vulnweb.com.

**Proof of Concept:**
```http
GET / HTTP/1.1
Host: vulnweb.com
User-Agent: ReconX-Agent
```

**Impact:**
An attacker could exploit this vulnerability to cause unauthorized access, service disruption, or configuration modification.

**Remediation:**
Update the Web Service component to the latest stable version and review service configurations.

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2019-9022


## [Low] Vulnerable Service: Web Service (CVE-2019-9024)

**Target:**
vulnweb.com

**Endpoint:**
/

**Severity:**
Low

**CVE:**
CVE-2019-9024

**Description:**
A security vulnerability was identified on the service Web Service running on host vulnweb.com.

**Proof of Concept:**
```http
GET / HTTP/1.1
Host: vulnweb.com
User-Agent: ReconX-Agent
```

**Impact:**
An attacker could exploit this vulnerability to cause unauthorized access, service disruption, or configuration modification.

**Remediation:**
Update the Web Service component to the latest stable version and review service configurations.

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2019-9024


## [High] Vulnerable Service: PHP (CVE-2019-6977)

**Target:**
rest.vulnweb.com

**Endpoint:**
/

**Severity:**
High

**CVE:**
CVE-2019-6977

**Description:**
gdImageColorMatch in gd_color_match.c in the GD Graphics Library (aka LibGD) 2.2.5, as used in the imagecolormatch function in PHP before 5.6.40, 7.x before 7.1.26, 7.2.x before 7.2.14, and 7.3.x befo

**Proof of Concept:**
```http
GET / HTTP/1.1
Host: rest.vulnweb.com
User-Agent: ReconX-Agent
```

**Impact:**
An attacker could exploit this vulnerability to cause unauthorized access, service disruption, or configuration modification.

**Remediation:**
Update the PHP component to the latest stable version and review service configurations.

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2019-6977


## [Critical] Vulnerable Service: PHP (CVE-2019-9020)

**Target:**
rest.vulnweb.com

**Endpoint:**
/

**Severity:**
Critical

**CVE:**
CVE-2019-9020

**Description:**
An issue was discovered in PHP before 5.6.40, 7.x before 7.1.26, 7.2.x before 7.2.14, and 7.3.x before 7.3.1. Invalid input to the function xmlrpc_decode() can lead to an invalid memory access (heap o

**Proof of Concept:**
```http
GET / HTTP/1.1
Host: rest.vulnweb.com
User-Agent: ReconX-Agent
```

**Impact:**
An attacker could exploit this vulnerability to cause unauthorized access, service disruption, or configuration modification.

**Remediation:**
Update the PHP component to the latest stable version and review service configurations.

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2019-9020


## [Critical] Vulnerable Service: PHP (CVE-2019-9021)

**Target:**
rest.vulnweb.com

**Endpoint:**
/

**Severity:**
Critical

**CVE:**
CVE-2019-9021

**Description:**
An issue was discovered in PHP before 5.6.40, 7.x before 7.1.26, 7.2.x before 7.2.14, and 7.3.x before 7.3.1. A heap-based buffer over-read in PHAR reading functions in the PHAR extension may allow an

**Proof of Concept:**
```http
GET / HTTP/1.1
Host: rest.vulnweb.com
User-Agent: ReconX-Agent
```

**Impact:**
An attacker could exploit this vulnerability to cause unauthorized access, service disruption, or configuration modification.

**Remediation:**
Update the PHP component to the latest stable version and review service configurations.

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2019-9021


## [High] Vulnerable Service: PHP (CVE-2019-9022)

**Target:**
rest.vulnweb.com

**Endpoint:**
/

**Severity:**
High

**CVE:**
CVE-2019-9022

**Description:**
An issue was discovered in PHP 7.x before 7.1.26, 7.2.x before 7.2.14, and 7.3.x before 7.3.2. dns_get_record misparses a DNS response, which can allow a hostile DNS server to cause PHP to misuse memc

**Proof of Concept:**
```http
GET / HTTP/1.1
Host: rest.vulnweb.com
User-Agent: ReconX-Agent
```

**Impact:**
An attacker could exploit this vulnerability to cause unauthorized access, service disruption, or configuration modification.

**Remediation:**
Update the PHP component to the latest stable version and review service configurations.

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2019-9022


## [Critical] Vulnerable Service: PHP (CVE-2019-9023)

**Target:**
rest.vulnweb.com

**Endpoint:**
/

**Severity:**
Critical

**CVE:**
CVE-2019-9023

**Description:**
An issue was discovered in PHP before 5.6.40, 7.x before 7.1.26, 7.2.x before 7.2.14, and 7.3.x before 7.3.1. A number of heap-based buffer over-read instances are present in mbstring regular expressi

**Proof of Concept:**
```http
GET / HTTP/1.1
Host: rest.vulnweb.com
User-Agent: ReconX-Agent
```

**Impact:**
An attacker could exploit this vulnerability to cause unauthorized access, service disruption, or configuration modification.

**Remediation:**
Update the PHP component to the latest stable version and review service configurations.

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2019-9023


## [High] Vulnerable Service: PHP (CVE-2019-9024)

**Target:**
rest.vulnweb.com

**Endpoint:**
/

**Severity:**
High

**CVE:**
CVE-2019-9024

**Description:**
An issue was discovered in PHP before 5.6.40, 7.x before 7.1.26, 7.2.x before 7.2.14, and 7.3.x before 7.3.1. xmlrpc_decode() can allow a hostile XMLRPC server to cause PHP to read memory outside of a

**Proof of Concept:**
```http
GET / HTTP/1.1
Host: rest.vulnweb.com
User-Agent: ReconX-Agent
```

**Impact:**
An attacker could exploit this vulnerability to cause unauthorized access, service disruption, or configuration modification.

**Remediation:**
Update the PHP component to the latest stable version and review service configurations.

**References:**
- https://nvd.nist.gov/vuln/detail/CVE-2019-9024


## [Medium] HTTP Traffic Anomaly

**Target:**
vulnweb.com

**Endpoint:**
/

**Severity:**
Medium

**CVE:**
N/A

**Description:**
HTTP traffic anomaly detected on subdomain vulnweb.com. Signals: 

**Proof of Concept:**
```http
GET / HTTP/1.1
Host: vulnweb.com
User-Agent: ReconX-Agent
```

**Impact:**
Unusual HTTP response behaviors or configurations could indicate malicious activity, configuration drift, or information leaks.

**Remediation:**
Review the HTTP traffic logs and server configurations on the specified host.

**References:**
N/A


## [Medium] HTTP Traffic Anomaly

**Target:**
www.vulnweb.com

**Endpoint:**
/

**Severity:**
Medium

**CVE:**
N/A

**Description:**
HTTP traffic anomaly detected on subdomain www.vulnweb.com. Signals: 

**Proof of Concept:**
```http
GET / HTTP/1.1
Host: www.vulnweb.com
User-Agent: ReconX-Agent
```

**Impact:**
Unusual HTTP response behaviors or configurations could indicate malicious activity, configuration drift, or information leaks.

**Remediation:**
Review the HTTP traffic logs and server configurations on the specified host.

**References:**
N/A


## [Medium] HTTP Traffic Anomaly

**Target:**
rest.vulnweb.com

**Endpoint:**
/

**Severity:**
Medium

**CVE:**
N/A

**Description:**
HTTP traffic anomaly detected on subdomain rest.vulnweb.com. Signals: 

**Proof of Concept:**
```http
GET / HTTP/1.1
Host: rest.vulnweb.com
User-Agent: ReconX-Agent
```

**Impact:**
Unusual HTTP response behaviors or configurations could indicate malicious activity, configuration drift, or information leaks.

**Remediation:**
Review the HTTP traffic logs and server configurations on the specified host.

**References:**
N/A


## [Medium] HTTP Traffic Anomaly

**Target:**
test.vulnweb.com

**Endpoint:**
/

**Severity:**
Medium

**CVE:**
N/A

**Description:**
HTTP traffic anomaly detected on subdomain test.vulnweb.com. Signals: 

**Proof of Concept:**
```http
GET / HTTP/1.1
Host: test.vulnweb.com
User-Agent: ReconX-Agent
```

**Impact:**
Unusual HTTP response behaviors or configurations could indicate malicious activity, configuration drift, or information leaks.

**Remediation:**
Review the HTTP traffic logs and server configurations on the specified host.

**References:**
N/A

