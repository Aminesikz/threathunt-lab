# D002: PHP web server starts a shell or tool (Linux)

| | |
|---|---|
| **Rule** | [`sigma/php_web_server_starts_shell.yml`](sigma/php_web_server_starts_shell.yml) |
| **Based on** | Hunt [H002](../hunts/H002-php-web-server-children.md), [PHP2Shell research](../docs/php2shell-research.md) |
| **Status / level** | experimental / high |
| **Results** | [`reports/D002-evaluation.md`](../reports/D002-evaluation.md) |

## What it detects

A PHP web server process starting a shell or a discovery/download tool. After
PHP2Shell, attackers were reported trying exactly this (`id`, `uname -a`,
`wget`). A web request should rarely need it.

## The logic

```text
web server parent  AND  shell or tool child  AND NOT  PHP's mail command
```

| Part | What the rule checks |
|---|---|
| Web server parent | Parent path ends with `/apache2`, `/httpd`, `/frankenphp`, `/lsphp`, or contains `/php-fpm`, `/php-cgi` |
| Shell or tool | Path ends with `/sh`, `/bash`, `/dash`, `/id`, `/uname`, `/whoami`, `/hostname`, `/wget`, `/curl` |
| Mail exclusion | Command line is exactly `sh -c /usr/sbin/sendmail -t -i` |

Why (from the hunt):

- **`contains` for PHP-FPM**, because the path has the version in it
  (`/usr/sbin/php-fpm8.2`).
- **No plain `php`**: that's command-line scripts run by cron or admins.
- **`/dash`**: on Debian and Ubuntu `sh` is really dash.
- **Tools, not just shells**: PHP can start `curl` directly (`php-evt-0010`).
- **`/id` with the slash**, so `/usr/bin/identify` doesn't match.
- **Exact mail exclusion**, so `sendmail ...; curl ...` still alerts
  (`php-evt-0012`).
- **One hop only.** `uname` started by the shell (`php-evt-0008`) doesn't
  alert, because its parent is `sh`. The alert on the shell already covers it.

## Fields it needs

| Sigma field | ECS field | In our data? |
|---|---|---|
| `ParentImage` | `process.parent.executable` | Yes, except `php-evt-0013` |
| `Image` | `process.executable` | Yes |
| `CommandLine` | `process.command_line` | Yes |

## ATT&CK mapping

| Technique | Why |
|---|---|
| T1190 Exploit Public-Facing Application | What usually comes before this |
| T1059.004 Unix Shell | The shell child |
| T1033, T1082 Discovery | `id`, `whoami`, `uname`, `hostname` |
| T1105 Ingress Tool Transfer | `wget`, `curl` |

## Elastic version (EQL)

sigma-cli has no ECS pipeline for Linux, so the lab has its own:
[`pipelines/ecs_linux.yml`](pipelines/ecs_linux.yml). It renames the three
Sigma fields to ECS. Without it, the query would search for a field called
`ParentImage`, which doesn't exist in Elastic.

```bash
.venv/bin/sigma check detections/sigma/php_web_server_starts_shell.yml
.venv/bin/sigma convert -t eql -p detections/pipelines/ecs_linux.yml detections/sigma/php_web_server_starts_shell.yml
```

`sigma check`: 0 errors, 0 issues. The converted query:

```eql
any where ((process.parent.executable like~ ("*/apache2", "*/httpd", "*/frankenphp", "*/lsphp")) or (process.parent.executable like~ ("*/php-fpm*", "*/php-cgi*"))) and (process.executable like~ ("*/sh", "*/bash", "*/dash", "*/id", "*/uname", "*/whoami", "*/hostname", "*/wget", "*/curl")) and (not process.command_line:"sh -c /usr/sbin/sendmail -t -i")
```

**Not run on a real cluster.**

## Expected false positives

- **Image processing** (ImageMagick through a shell), like `php-evt-0006`.
  If it's noisy, exclude that exact command pattern on that server only.
- **Admin panels and plugins** that run system commands (backups, updates).
- **Health checks** that run `hostname` or `id`.

## Triage

1. Which server, and is it running a vulnerable PHP version (`php-versions`)?
2. What did the command do? Discovery and downloads from an IP are worse
   than a known tool.
3. Look at the server's timeline (H002 Q4) for more commands around it.
4. Next data to get: web access logs for that time, files in `/tmp`, outbound
   connections.

## Known gaps

- **Missing parent path** (`php-evt-0013`): some log sources only give the
  parent's name. The rule misses it; the hunt doesn't.
- **Tools not on the list**: `python3`, `perl`, `nc`, `busybox`, or a
  downloaded binary run straight from PHP.
- **Attackers who stay inside PHP**: no process starts, nothing to detect.
- **Other ways to run PHP**: a custom PHP-FPM path or a renamed binary.
- **Doesn't say how it happened**: PHP2Shell, another bug and a web shell all
  look the same here.

## Testing

[`detection_php.py`](../src/threathunt_lab/detection_php.py) does the same
checks in Python. Tests in
[`test_detection_php.py`](../tests/test_detection_php.py) check that:

- its patterns match the Sigma file
- the EQL above is exactly what sigma-cli produces
- it catches every web server type and ignores look-alikes (`php8.3` CLI,
  `identify`, `rotatelogs`)
- the mail exclusion is exact
- missing fields don't crash it

## Results (Milestone 8)

`python -m threathunt_lab evaluate --detection D002` runs it on the 13 events
and compares with the labels ([report](../reports/D002-evaluation.md)):

- **No false positives.** PHP mail, cron PHP and the `uname` grandchild didn't alert.
- **One miss: `php-evt-0013`**, the event without a parent path, as expected.
- **`php-evt-0006` alerted**: correct for this rule, but it's a legitimate
  image resize (a "benign true positive").
- **Optimistic**, like D001: the rule was built from the hunt on these same
  events.

How an analyst would follow up a D002 alert:
[investigation walkthrough](../docs/php2shell-investigation.md).
