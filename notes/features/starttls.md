# STARTTLS

- `--starttls <proto>` runs a plaintext exchange inside `connect_tls`, then passes the TCP stream to rustls.
- Sources: RFC 3207 (SMTP), RFC 2033 (LMTP), RFC 2595 (IMAP `STARTTLS`, POP3 `STLS`), RFC 4217 (FTP `AUTH TLS`),
  RFC 4642 (NNTP), RFC 5804 (ManageSieve), PostgreSQL SSLRequest (length 8, code 80877103).
- SMTP/LMTP greet with `EHLO [local-address]`, the RFC 5321 section 4.1.3 address literal; IPv6 uses `[IPv6:addr]`.
- Reply parsing: `ddd-` continues; the final line starts with the same code and no `-`. FTP continuation
  lines without a code are accepted (RFC 959).
- Bytes buffered after the final reply fail with `starttls_unexpected_data`. Mutation check: without this
  check the `BufReader` buffer is dropped and the handshake succeeds; the check adds diagnostics, not
  injection resistance.
- Negotiation input is capped at 64 KiB. `--connect-timeout` covers TCP connect, negotiation, and handshake.
- Script `starttls` step: `mem::replace` swaps the boxed stream for `tokio::io::empty()` during the handshake.
  A timed-out handshake leaves the placeholder; the step is terminal.
- Pending script plaintext is rejected: STARTTLS response injection (Poddebniak et al., USENIX Security 2021);
  unconsumed reply bytes also race with the ClientHello.
- Scripts with a `starttls` step load certificate files before connecting.

## Verification

- `scripts/test_starttls.py`, 15 tests: 8 protocol exchanges; rejections for 6 protocols; injected plaintext
  (smtp, postgres); EOF, malformed reply, 64 KiB cap; negotiation timeout; unknown issuer; `--tls-info`;
  `--dump-cert`; usage errors; `examples/smtp-starttls.toml`; pending script plaintext; second upgrade.
- Live 2026-11-18: `smtp.gmail.com:587 --starttls smtp --tls-info` returned TLSv1_3, verified,
  `CN=smtp.gmail.com`, 0 application bytes. `imap.gmail.com:143` timed out at TCP connect.
