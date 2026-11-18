# Completed

- Added `--starttls` negotiation for SMTP, LMTP, IMAP, POP3, FTP, NNTP, ManageSieve, and PostgreSQL.
- Added a script `starttls` step; unconsumed plaintext before the upgrade is rejected.

- Added direct trust for an exactly imported CA-marked server certificate while retaining identity, validity, purpose, and TLS signature checks.

- Added JSON/TOML conversation scripts with one validated step model.
- Added literal alternatives, success/failure branches, EOF handling, exact/binary sends, and per-step deadlines.
- Added bounded matching buffers, global limit enforcement, per-step JSON traces, and SMTP examples.

- Added total deadlines and received application byte limits with exit code 4.
- Added structured JSON results with bounded response capture and typed failure reasons.
- Added TLS SNI and certificate identity overrides via `--server-name`.
- Added write-side shutdown after commands or stdin, while retaining reply reads.
- Added TLS inspection and certificate metadata to JSON TLS results.
- Updated SAN extension lookup for the `x509-cert` 0.3 API.

- Added repeatable `--cacert` imports for PEM certificates, PEM bundles, and DER certificates.
- Added `--no-default-ca` to exclude bundled CAs while preserving certificate verification.
- Added `--dump-cert` to export an unverified server leaf certificate as PEM to a new file or stdout.
- Added local TLS regression tests for certificate imports, exports, and validation errors.
