# telnetz

Telnet-like command line client for TCP and TLS sockets.

```sh
cargo install --path .
telnetz example.com 443 --tls
```

At a terminal it reads lines interactively (`/quit` exits). With piped stdin or `-c`
it sends the input and prints the reply until the server closes, `-w` expires
or `--expect` matches, so it can be used from scripts and AI agents.

```sh
telnetz -q --expect 220 -w 5 mail.example.com 25            # exit 0 if banner seen, 3 if not
telnetz -q -w 1 -c PING localhost 6379
printf 'GET / HTTP/1.0\r\n\r\n' | telnetz -q --raw -w 5 example.com 80
```

Exit codes: 0 ok, 1 connection/IO error, 2 usage error, 3 `--expect` not seen.
See `telnetz --help`.

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
match the certificate's subject alternative name. `--cacert` requires `--tls`
and cannot be combined with `--insecure`.

Use `--no-default-ca` to trust only certificates supplied with `--cacert`:

```sh
telnetz localhost 443 --tls --no-default-ca --cacert server.crt
```

This option requires `--tls`. Certificate verification remains enabled; without
any `--cacert` files, no server certificate is trusted.

`--dump-cert` saves the server's leaf certificate as PEM and exits without reading
stdin or sending application data. It fetches certificates without checking trust,
hostname, or expiry. It requires `--tls` and cannot be combined with `--cacert`,
`--command`, or `--expect`. Existing files are preserved. Use `--dump-cert -` to
write PEM to stdout.

## Agent skill

`skills/telnetz/SKILL.md` teaches coding agents to use telnetz. For Claude Code:

```sh
cp -r skills/telnetz ~/.claude/skills/
```
