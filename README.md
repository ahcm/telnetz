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

## Agent skill

`skills/telnetz/SKILL.md` teaches coding agents to use telnetz. For Claude Code:

```sh
cp -r skills/telnetz ~/.claude/skills/
```
