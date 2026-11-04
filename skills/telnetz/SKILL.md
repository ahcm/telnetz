---
name: telnetz
description: Talk to raw TCP or TLS sockets from the shell with telnetz — send lines to line-based protocols (SMTP, IMAP, POP3, Redis, HTTP/1.x, IRC, memcached, custom servers), check banners, and test whether a port or TLS endpoint answers. Use when you need to probe a network service or speak a text protocol by hand.
---

# telnetz

`telnetz <host> <port> [options]` connects to a TCP socket, optionally over TLS.
Server output goes to stdout. Status and errors go to stderr.

## Rules for non-interactive use

- Always pass `-q` so stdout contains only server bytes.
- Bound the run with `--max-time <secs>`; use `--max-bytes <bytes>` to cap output.
  `-w` only limits idle time. `--expect` alone imposes no deadline.
- Send input with repeated `-c <line>`, or pipe it on stdin. With `-c`, stdin is not read.
- Lines are sent with CRLF. Use `--lf` for LF-only protocols, `--raw` to pipe exact bytes.

## Options

| Option | Effect |
|---|---|
| `--tls` | TLS with webpki roots; SNI is the host name |
| `--server-name <NAME>` | Override SNI and certificate verification identity; connect address stays unchanged; needs `--tls` |
| `--insecure` | Skip certificate verification (needs `--tls`) |
| `--no-default-ca` | Ignore bundled CAs; verified TLS trusts only `--cacert` files (needs `--tls`) |
| `--cacert <FILE>` | Add trusted PEM/DER certificates; repeatable, needs `--tls`, conflicts with `--insecure` |
| `--dump-cert <FILE>` | Fetch unverified leaf certificate as PEM and exit; needs `--tls`; `-` writes stdout; preserves existing files |
| `-c, --command <LINE>` | Send LINE; repeatable, sent in order right after connecting |
| `--expect <TEXT>` | Exit 0 once TEXT appears in the output; exit 3 if the connection ends first |
| `-w, --timeout <SECS>` | Stop after SECS with no traffic (fractions allowed) |
| `--connect-timeout <SECS>` | Connect + TLS handshake limit, default 10 |
| `--max-time <SECS>` | Total deadline, including blocked reads/writes; exits 4 |
| `--max-bytes <BYTES>` | Positive received application byte cap; exits 4 unless `--expect` matches |
| `--json` | One result object with termination reason, phase, timings, counts, and response; defaults to 1 MiB receive cap |
| `--lf` | Terminate lines with `\n` instead of `\r\n` |
| `--raw` | Forward stdin unchanged |
| `-q, --quiet` | Suppress status messages |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Remote closed, idle timeout, or `--expect` matched |
| 1 | Connect failure, connect timeout, TLS or I/O error |
| 2 | Usage error |
| 3 | `--expect` text never appeared |
| 4 | Total time or receive byte limit reached |

## Examples

```sh
# Is the port open and does it speak SMTP?
telnetz -q --expect '220' -w 5 mail.example.com 25

# HTTP request over TLS; the server closes after the response
telnetz -q --tls -w 5 -c 'GET / HTTP/1.1' -c 'Host: example.com' -c 'Connection: close' -c '' example.com 443

# Obtain a self-signed server certificate; compare its fingerprint through a trusted channel
telnetz -q --tls --dump-cert server.crt localhost 8443
openssl x509 -in server.crt -noout -fingerprint -sha256

# Trust the checked server certificate
telnetz -q --tls --cacert server.crt --expect ready -w 5 localhost 8443

# Trust only the checked server certificate
telnetz -q --tls --no-default-ca --cacert server.crt --expect ready -w 5 localhost 8443

# Redis
telnetz -q -w 1 -c PING -c 'INFO server' localhost 6379

# Multi-line input from a heredoc
telnetz -q -w 2 imap.example.com 143 <<'IN'
a1 CAPABILITY
a2 LOGOUT
IN

# Exact bytes, no line translation
printf 'stats\r\n' | telnetz -q -w 1 --raw localhost 11211
```

## Notes

- All `-c` lines are sent immediately; telnetz does not wait for a reply between lines.
  For protocols that reject pipelining, run one command per invocation or pace a stdin pipe
  (`{ echo A; sleep 1; echo B; } | telnetz ...`).
- `--expect` stops at the read that contains the text. Output after it is not printed.
- `--json` captures responses as `output_base64` and nullable `output_utf8`. It suppresses status messages.
  Check `exit_code`, `phase`, `reason`, and `matched`; idle timeout and EOF remain distinct even with exit 0.
- Use `--cacert server.crt` for self-signed servers; hostname and expiry checks still apply.
- Add `--no-default-ca` to exclude bundled CAs. With verification enabled and no `--cacert`, all server certificates are rejected.
- `--dump-cert` skips trust, hostname, and expiry checks and sends no application data.
  It cannot be combined with `--cacert`, `--command`, or `--expect`.
- `--insecure` skips certificate verification; it is for test servers only.
- Interactive mode (a human at a terminal) is used only when stdin is a TTY and no `-c` is given.
