# Open issues

- Add incremental JSONL session control using the script operations.
- Discuss regex and binary expectation patterns, named captures, and variable substitution.
- Define line and length framing before adding an unexpected-message fallback.
- Discuss bounded loops/retries and reconnection semantics for stateful commands.
- Add explicit secret inputs and transcript redaction for authenticated probes.
- Add a published script schema and a validation-only CLI mode.
- Add built-in STARTTLS for XMPP, LDAP, and MySQL; scripts need binary expectations for LDAP/MySQL.
- Discuss an `EHLO` name option for `--starttls smtp`; the argument is the local address literal.
