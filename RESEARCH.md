# TLS certificate imports

- `--tls --cacert server.crt` adds certificates to the built-in webpki roots for one invocation.
- `--no-default-ca` excludes built-in roots; verified TLS then trusts only `--cacert` files.
- With `--no-default-ca` and no imported certificates, verification rejects server certificates with `UnknownIssuer`.
- `--no-default-ca` requires `--tls`; it does not change the verification bypass in `--insecure` or `--dump-cert` mode.
- Files may contain PEM certificates, a PEM bundle, or one DER certificate. `--cacert` is repeatable.
- rustls still verifies certificate signatures, validity, usage, and subject alternative names.
- Unreadable or invalid certificate files fail before connecting, with the file path in the error (exit 1).
- Missing `--tls`, conflicting `--insecure`, or a missing file argument is a usage error (exit 2).
- PEM decoding uses rustls's re-exported `pki_types::pem::PemObject`; no dependencies were added.

# TLS certificate export

- `--tls --dump-cert server.crt` saves the peer's leaf certificate as PEM and exits.
- `--dump-cert -` writes PEM to stdout. Status messages use stderr; `-q` suppresses them.
- Dump mode accepts untrusted, expired, or hostname-mismatched certificates. TLS handshake signatures are still verified.
- No application data is sent, and stdin is not read. `--cacert`, `--command`, and `--expect` conflict with dump mode.
- `--connect-timeout` bounds TCP connection establishment and the TLS handshake.
- Output files are created after a successful handshake, with exclusive creation. Existing files are preserved.
- Exported certificates require identity verification through a trusted channel before use with `--cacert`.
- PEM encoding uses `base64` 0.23 with 64-character lines and a trailing newline.

# Agent execution limits

- `--max-time` covers connection establishment, TLS handshake, session I/O, and certificate export.
- `--max-bytes` caps received application bytes; an expectation match within the cap takes precedence.
- Hard limits exit 4. Runtime shutdown does not wait for outstanding blocking stdin or rustyline reads.
- Local tests cover continuous traffic, open stdin, stalled TLS, blocked writes, and byte boundaries.

# Structured results

- `--json` emits schema version 1, including phase, termination reason, exit code, timings, counts, peer address, and response.
- Responses use lossless base64 and nullable UTF-8. JSON mode defaults to a 1 MiB application byte cap.
- Error classification uses typed I/O and rustls errors; certificate files use asynchronous reads.
- Final JSON output gets the remaining total deadline, with a minimum 100 ms reporting budget.
- Tests cover binary data, termination conditions, interrupted-write counts, certificate errors, file-loading deadlines, and blocked stdout.

# TLS identity override

- `--server-name` changes SNI and the certificate verification identity, independently of the connection address.
- Tests connect to loopback, check the SNI received by the server, reject a mismatched override, and export with an override.

# Input EOF handling

- `--shutdown-write` performs TCP write shutdown or sends TLS `close_notify` after non-interactive input ends.
- Reading continues after shutdown. The default behavior still keeps the sending side open at input EOF.
- Tests cover commands, normalized lines, raw binary input, empty input, opt-in behavior, and a TLS peer that replies after EOF.

# TLS inspection

- `--tls-info` returns negotiated protocol/cipher and metadata for the server's presented certificate chain, then exits.
- Verification stays enabled by default. Explicit `--insecure` is reported as skipped verification.
- SHA-256 fingerprints use `sha2`; certificate names, SANs, and validity use `x509-cert`.
- `x509-cert` 0.3 renames `TbsCertificate::get` to `get_extension`; certificate accessors return references.
- Metadata parse failures are reported per certificate, independently of handshake verification.
- Tests compare fingerprints with Python hashlib and validity timestamps with OpenSSL output.
- Inspection tests cover TLS 1.2/1.3, typed DNS/IPv4/IPv6/URI/email SANs, chain order, expired certificates, and open stdin with no application data.

# Conversation scripts

- JSON and TOML deserialize into one strict model; all branches are validated before connecting.
- Literal alternatives select the earliest completed match, with declaration order breaking ties.
- Matching scans new bytes plus pattern overlap; bytes after a match and unmatched bytes after recovery are preserved.
- Global limits and transport errors terminate; expectation timeout/EOF handlers retain their original outcomes in traces.
- Source size, branch depth, step count, case count, and the default receive buffer are bounded.
- Local tests cover both formats, fragmented/coalesced replies, branch order, handler precedence, limits, binary data, TLS, and open stdin.

## Verification

All 57 regression tests passed against the release binary: 22 conversation tests,
14 agent/TCP tests, and 21 TLS tests. The release build, Cargo tests, Clippy with
warnings denied, nightly formatting, and whitespace checks passed.

```sh
cargo build --offline
python3 scripts/test_tls.py
python3 scripts/test_agent.py
python3 scripts/test_scripts.py
cargo test --offline
cargo clippy --offline --all-targets -- -D warnings
cargo +nightly fmt --check
git diff --check
```

The Python suite requires OpenSSL and loopback socket access. It generates temporary
certificates and tests imports, export/import round trips,
stdout export, untrusted and expired certificates, hostname mismatches, invalid
files and options, preserved output files, failed connections, no application data,
open stdin, and the existing `--insecure` mode. Set `TELNETZ_BIN` to test a different build.
Import formats, repeated files, untrusted certificates, hostname mismatches, and expired
certificates are tested with bundled CAs both enabled and disabled.

Live check on 2026-11-02: `example.com:443` completed TLS with the bundled roots.
Adding `--no-default-ca` without `--cacert` rejected the same endpoint with
`UnknownIssuer`. No application data was sent.
