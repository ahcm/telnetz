# telnetz

Telnet-like command line client for TCP and TLS sockets.

```sh
cargo install --path .
telnetz example.com 443 --tls
```

At a terminal it reads lines interactively (`/quit` exits). With piped stdin or `-c`
it sends the input and prints the reply until the server closes, `-w` expires
or `--expect` matches, so it can be used from scripts and AI agents.

Use `--script <file.json|file.toml>` for sequential sends, buffered expectations,
alternate replies, and timeout/EOF handlers. Both formats share one schema.

```sh
telnetz localhost 25 --script examples/smtp.toml --json --max-time 10
```

See [SCRIPTING.md](SCRIPTING.md) and the equivalent [JSON](examples/smtp.json) and
[TOML](examples/smtp.toml) examples. Script mode defaults to a 1 MiB receive cap.

```sh
telnetz -q --expect 220 -w 5 mail.example.com 25            # exit 0 if banner seen, 3 if not
telnetz -q -w 1 -c PING localhost 6379
printf 'GET / HTTP/1.0\r\n\r\n' | telnetz -q --raw -w 5 example.com 80
```

`--max-time <seconds>` bounds the entire operation, including connection,
handshake, and blocked reads/writes. `--max-bytes <positive integer>` limits
received application bytes. Reaching either limit exits 4. An `--expect` match
within the byte limit succeeds, including at the exact boundary. Certificate
exports and TLS inspection do not receive application bytes, so their output is
outside the byte cap.

Exit codes: 0 ok, 1 connection/IO error, 2 usage error, 3 `--expect` not seen,
4 hard limit reached.
See `telnetz --help`.

Use `--json` for one result object on stdout, with no status messages. It includes
`schema_version`, `ok`, `exit_code`, `phase`, `reason`, `error`, `elapsed_ms`,
`bytes_sent`, `bytes_received`, `matched`, and `peer_addr`. `output_base64` preserves
all received bytes; `output_utf8` contains the same response if valid UTF-8,
otherwise null. JSON mode defaults to a 1 MiB receive cap; `--max-bytes` overrides it.
Usage and connection failures also produce JSON. `--help` remains human-readable.
`--json` can export certificates to files, but conflicts with `--dump-cert -`.
The total deadline allows up to 100 ms extra to emit the final JSON result. If
stdout blocks past that budget, output may be incomplete and the process exits 4.

```sh
telnetz localhost 6379 --json --max-time 3 -c PING
```

For a self-signed server, obtain its certificate first:

```sh
telnetz localhost 443 --tls --dump-cert server.crt
openssl x509 -in server.crt -noout -fingerprint -sha256
```

Compare the fingerprint with a value obtained through a trusted channel. Then
trust the certificate for the connection:

```sh
telnetz localhost 443 --tls --cacert server.crt
```

`--cacert` accepts PEM certificates, PEM bundles, or a DER certificate. Repeat it
to trust multiple files. These certificates are added to the built-in public
roots for this invocation. Hostname and expiry checks still apply; the host must
match the certificate's subject alternative name. `--cacert` requires `--tls` or `--starttls`
and cannot be combined with `--insecure`.

Some devices use a certificate marked `CA:TRUE` as their TLS server certificate.
An identical certificate supplied with `--cacert` can be trusted directly in this
case. The exception requires an exact DER match. Validity dates, server-authentication
purpose, unrecognized critical extensions, hostname SANs, and TLS handshake signatures
are still checked. Other certificates continue through normal chain verification.

When connecting by IP to a device whose certificate contains only DNS names, use
`--server-name` with a name from its SANs:

```sh
telnetz 192.168.1.1 443 --tls --tls-info --cacert fritz.ca --server-name fritz.box
```

Use `--no-default-ca` to trust only certificates supplied with `--cacert`:

```sh
telnetz localhost 443 --tls --no-default-ca --cacert server.crt
```

This option requires `--tls` or `--starttls`. Certificate verification remains enabled; without
any `--cacert` files, no server certificate is trusted.

`--dump-cert` saves the server's leaf certificate as PEM and exits without reading
stdin or sending application data. It fetches certificates without checking trust,
hostname, or expiry. It requires `--tls` or `--starttls` and cannot be combined with `--cacert`,
`--command`, or `--expect`. Existing files are preserved. Use `--dump-cert -` to
write PEM to stdout.

Use `--server-name <name>` with `--tls` or `--starttls` to set both SNI and the certificate
verification identity while connecting to a different address:

```sh
telnetz 127.0.0.1 8443 --tls --server-name service.example --cacert server.crt
```

JSON results include the effective TLS `server_name` separately from `peer_addr`.

`--tls-info` completes a verified TLS handshake, prints certificate and connection
metadata as JSON, and exits without reading stdin or sending application data.
Use `--json` to include it under `tls` in the full session result instead. Regular
`--json --tls` sessions also include TLS metadata. The TLS object reports
`protocol_version`, `cipher_suite`, `verification`, and the server's presented
`certificates` in leaf-first order. Certificate fields include SHA-256 fingerprints,
subject, issuer, serial number, typed SANs, UTC validity dates, Unix timestamps,
and expiry/not-yet-valid flags. Metadata decoding errors appear as `parse_error`
without changing the connection's verification result.

```sh
telnetz localhost 8443 --tls --cacert server.crt --tls-info --json --max-time 3
```

For an untrusted or expired server, explicitly use `--insecure` to inspect it;
the result reports `verification: "skipped"`. `--tls-info` requires `--tls` or `--starttls` and
cannot be combined with `--dump-cert`, `--command`, or `--expect`.

## STARTTLS

`--starttls <proto>` connects in plaintext, negotiates the upgrade, then performs
the TLS handshake. Commands, stdin, `--expect`, and scripts start after the handshake.

```sh
telnetz mail.example.com 587 --starttls smtp --tls-info --json --max-time 10
telnetz mail.example.com 587 --starttls smtp -c 'EHLO client.example' --expect '250 ' -w 5
```

| Protocol | Exchange before the handshake |
|---|---|
| `smtp`, `lmtp` | greeting `220`; `EHLO`/`LHLO [local-address]` → `250`; `STARTTLS` → `220` |
| `imap` | greeting `* OK`; `a1 STARTTLS` → `a1 OK` |
| `pop3` | greeting `+OK`; `STLS` → `+OK` |
| `ftp` | greeting `220`; `AUTH TLS` → `234` (control connection only) |
| `nntp` | greeting `200` or `201`; `STARTTLS` → `382` |
| `sieve` | greeting `OK`; `STARTTLS` → `OK` (RFC 5804) |
| `postgres` | SSLRequest → `S` |

All TLS options apply, including `--dump-cert` and `--tls-info`. `--starttls`
conflicts with `--tls`. Negotiation bytes are neither printed nor counted in
`bytes_sent`, `bytes_received`, or `--max-bytes`. Negotiation is limited to 64 KiB
and to `--connect-timeout`. SMTP and LMTP sessions must repeat `EHLO`/`LHLO` after
the handshake (RFC 3207).

Failures exit 1 in phase `starttls`:

| Reason | Condition |
|---|---|
| `starttls_rejected` | Negative or unexpected reply; quoted in `error` |
| `starttls_protocol_error` | Malformed reply, EOF, or 64 KiB exceeded |
| `starttls_unexpected_data` | Plaintext after the final reply (response injection) |

Certificate and handshake failures report phase `tls`, as with `--tls`. For other
protocols, use a script `starttls` step; see [SCRIPTING.md](SCRIPTING.md#starttls).

`--shutdown-write` closes the sending side after all `-c` commands or piped input
have been sent, including empty stdin. It continues receiving replies until EOF,
an expectation match, or a limit. With TLS it sends `close_notify`; the peer must
support replying after that notification. Without this flag, input EOF keeps the
sending side open.

## Agent skill

`skills/telnetz/SKILL.md` teaches coding agents to use telnetz. For Claude Code:

```sh
cp -r skills/telnetz ~/.claude/skills/
```
