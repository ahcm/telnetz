# Completed

- Added total deadlines and received application byte limits with exit code 4.

- Added repeatable `--cacert` imports for PEM certificates, PEM bundles, and DER certificates.
- Added `--no-default-ca` to exclude bundled CAs while preserving certificate verification.
- Added `--dump-cert` to export an unverified server leaf certificate as PEM to a new file or stdout.
- Added local TLS regression tests for certificate imports, exports, and validation errors.
