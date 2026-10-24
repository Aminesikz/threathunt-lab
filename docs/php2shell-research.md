# PHP2Shell: research notes

Researched on 24 Oct 2026. **Confirmed** = from PHP or the CVE records.
**Reported** = a security company says so, not checked by me.

## What it is

Two bugs in PHP itself (not in a PHP app), fixed on 21 Oct 2026. Both let an
attacker run code on the server **without logging in**, as the web server
user (usually `www-data` on Linux). **Confirmed**

| CVE | PHP's name | In short |
|---|---|---|
| CVE-2026-109618 | RCE via OOM corruption | A crafted upload request makes PHP run out of memory and leaves broken data behind |
| CVE-2026-109619 | RCE via stale global state | PHP reuses memory from a previous request after it was freed |

Both are rated 9.2 (Critical). The attack works before any app code runs.

## Who is affected

| Branch | Fixed in |
|---|---|
| 8.5 | 8.5.12 |
| 8.4 | 8.4.27 |
| 8.3 | 8.3.36 |
| 8.2 | 8.2.35 |
| 8.1 and older | No PHP update. Needs a vendor fix or an upgrade |

Apache with **mod_php** is the highest risk: PHP showed a full attack working
on it. PHP-FPM is also affected. **Confirmed**

## Is it being exploited?

Sources don't agree:

- watchTowr says its honeypots saw exploitation. **Reported**
- Arctic Wolf saw attackers *try* to run `id`, `uname -a` and download files
  with `wget` / `curl`, but couldn't confirm it worked. **Reported**
- Not in CISA's list of exploited vulnerabilities (checked 24 Oct).

## What this lab can and can't see

The lab only has **process start events**. So:

| Can see | Can't see |
|---|---|
| A PHP process (`php-fpm`, `apache2`) starting `sh`, `id`, `uname`, `wget` or `curl` | The attack request (needs web server logs) |
| | Files dropped on disk (needs file events) |
| | Downloads and connections (needs network events) |
| | An attacker who only steals data from memory and runs no commands |

**Hypothesis for H002 (Milestone 7):** if an attacker got in and ran
commands, a PHP process will be the parent of a shell or tool.

## ATT&CK

| Technique | Why |
|---|---|
| T1190 Exploit Public-Facing Application | The bug itself |
| T1059.004 Unix Shell | Running commands |
| T1033 / T1082 Discovery | `id`, `uname -a` |
| T1105 Ingress Tool Transfer | `wget` / `curl` downloads |

## Remediation checklist

- [ ] Find every PHP server, internet-facing first (`python -m threathunt_lab php-versions`)
- [ ] Update PHP to a fixed version, or install the vendor's fixed package
- [ ] **Restart PHP** (PHP-FPM, Apache). Running processes keep the old code
- [ ] Can't update yet? Set `session.upload_progress.enabled = 0` and a low
      `post_max_size` in `php.ini`. This helps but doesn't fix it
- [ ] On servers that were exposed: look for PHP starting shells (H002),
      new files in `/tmp`, and outbound connections
- [ ] My suggestion: change passwords and API keys the server uses, since the
      bug can leak memory

**Note on the version check:** Linux distributions often fix PHP without
changing the version number, so "VULNERABLE" means "check this server".

## Sources

- PHP: [news item](https://www.php.net/index.php#2026-10-21-5),
  [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w),
  [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- CVE records: [CVE-2026-109618](https://www.cve.org/CVERecord?id=CVE-2026-109618),
  [CVE-2026-109619](https://www.cve.org/CVERecord?id=CVE-2026-109619)
- [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Wiz](https://www.wiz.io/blog/php2shell-php-rce),
  [Arctic Wolf](https://arcticwolf.com/resources/blog/php2shell-critical-php-vulnerabilities-enable-unauthenticated-remote-code-execution/),
  [watchTowr](https://watchtowr.com/intelligence/php-cve-2026-109618-faq/)
