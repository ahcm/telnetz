# Conversation scripts

```sh
telnetz localhost 25 --script examples/smtp.toml --json --max-time 10
telnetz localhost 25 --script examples/smtp.json --json --max-time 10
```

JSON and TOML files use the same schema and execution rules. The filename must
end in `.json` or `.toml`. Connection address, TLS options, line endings, and global
limits are supplied on the CLI. The complete file is validated before connecting.
Script mode reads no stdin and exits when the selected sequence finishes.

```toml
version = 1
step_timeout = 2

[[steps]]
name = 'greeting'
expect = '+OK'
timeout = 1
else = [{ fail = 'Expected a POP3 greeting' }]

[[steps]]
send_line = 'QUIT'

[[steps]]
expect_eof = true
```

`version` defaults to 1. `step_timeout` defaults to 2 seconds. Both the default
and per-step `timeout` must be finite positive seconds. Step timeouts cover that
step's I/O, including sends and output writes. Child steps get their own timeouts.
`name` is an optional label for diagnostics.

Each step has exactly one action:

| Action | Value | Behavior |
|---|---|---|
| `send_line` | String | Send UTF-8 followed by CRLF, or LF with `--lf` |
| `send` | String | Send exact UTF-8 bytes without a line ending |
| `send_base64` | Base64 string | Decode and send exact binary bytes |
| `expect` | Nonempty string or case array | Wait for a literal UTF-8 byte sequence |
| `expect_eof` | `true` | Read until the peer closes its sending side |
| `shutdown_write` | `true` | Close the sending side and continue the script |
| `fail` | String | Stop with exit 3 and this diagnostic |

An expectation step can also contain `then`, `else`, `on_timeout`, and `on_eof`.
Each is an array of steps. Other action types cannot have branches.

## Matching and branches

```json
{
  "steps": [
    {
      "expect": [
        {"text": "+OK", "then": [{"send_line": "QUIT"}]},
        {"text": "-ERR", "then": [{"fail": "Server rejected request"}]}
      ],
      "timeout": 2,
      "on_timeout": [{"fail": "No recognized reply"}],
      "on_eof": [{"fail": "Server closed the connection"}]
    }
  ]
}
```

Matching spans network reads. Bytes through the match are consumed from the
matching buffer. Subsequent bytes remain available to later expectations.
All bytes read remain in the JSON response or are streamed to stdout in plain mode.
Timeout and EOF handlers retain unmatched bytes for later expectations.

For multiple cases, the match that completes earliest in the byte stream wins.
Declaration order breaks ties at the same end offset. These rules apply even when
several replies arrive in one network read. Prefix alternatives can therefore
select the shorter match as soon as it completes.

The selected case's `then` runs first, followed by the expectation step's common
`then`. Execution then resumes after the expectation. A simple string expectation
can use the common `then` directly.

Timeout runs `on_timeout`, falling back to `else`. Premature EOF runs `on_eof`,
falling back to `else`. A handler that finishes successfully resumes the enclosing
sequence. An empty handler array explicitly accepts the condition. With no handler,
the expectation fails with exit 3. The success `then` does not run after recovery.
For `expect_eof`, EOF is success; only timeout requires recovery.

Receiving bytes that do not yet match does not run `else`. Known negative replies
belong in explicit cases. Transport errors, send/output timeouts, and hard limits
terminate execution. They do not run expectation failure handlers.

## Limits and diagnostics

Script mode defaults to a 1 MiB received byte cap, including without `--json`.
`--max-bytes` overrides it. Buffered matches can still finish at the cap; a step
that needs further input exits 4. `--max-time` bounds the entire operation and
cannot be handled by a script. `-w` adds an idle read timeout; it uses `on_timeout`
or `else`, while the per-step deadline still limits total waiting time.

Files are limited to 1 MiB, 4096 total steps across all branches, 16 nested branch
levels, and 128 cases per expectation. Unknown fields, invalid actions, invalid
timeouts, and unsupported versions are rejected before connecting.

Exit codes are 0 for a completed script, 1 for file/transport/output errors, 2 for
invalid scripts or CLI arguments, 3 for explicit failures or unhandled expectations,
and 4 for hard limits. Existing connection and TLS verification rules apply.

JSON results include `script.current_step` and a `script.steps` trace. Entries
contain the step path, optional name, action, outcome, handled flag, elapsed time,
and byte counts. Matches also include the case index and absolute byte offsets
`match_start` and `match_end`, with an exclusive end offset. Paths such as
`steps[2].expect[1].then[0]` identify nested failures. A recovered timeout or EOF
retains its original outcome in the trace. Cancellation finalizes the active entry.
`matched` reflects the most recent expectation outcome.

Script mode conflicts with `--command`, `--expect`, `--dump-cert`, `--tls-info`,
`--raw`, and `--shutdown-write`. Use script actions for exact bytes and write shutdown.
