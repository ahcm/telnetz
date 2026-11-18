use std::fmt;
use std::net::SocketAddr;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

/// Plaintext bytes accepted before the TLS handshake.
const MAX_RECEIVED: u64 = 64 * 1024;
/// PostgreSQL SSLRequest: length 8, request code 80877103.
const POSTGRES_SSL_REQUEST: [u8; 8] = [0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol
{
    Smtp,
    Lmtp,
    Imap,
    Pop3,
    Ftp,
    Nntp,
    Sieve,
    Postgres,
}

impl Protocol
{
    pub const NAMES: &str = "smtp, lmtp, imap, pop3, ftp, nntp, sieve, postgres";

    pub fn parse(name: &str) -> Option<Self>
    {
        Some(match name.to_ascii_lowercase().as_str()
        {
            "smtp" => Self::Smtp,
            "lmtp" => Self::Lmtp,
            "imap" => Self::Imap,
            "pop3" => Self::Pop3,
            "ftp" => Self::Ftp,
            "nntp" => Self::Nntp,
            "sieve" => Self::Sieve,
            "postgres" => Self::Postgres,
            _ => return None,
        })
    }
}

/// `reason` is the JSON termination reason.
#[derive(Debug)]
pub struct Error
{
    pub reason: &'static str,
    message: String,
}

impl Error
{
    pub fn new(reason: &'static str, message: impl Into<String>) -> Self
    {
        Self {
            reason,
            message: message.into(),
        }
    }

    fn rejected(command: &str, reply: &[u8]) -> Self
    {
        Self::new("starttls_rejected", format!("{command} rejected: {}", printable(reply)))
    }

    fn protocol(message: impl Into<String>) -> Self
    {
        Self::new("starttls_protocol_error", message)
    }
}

impl fmt::Display for Error
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

/// Lossy UTF-8 of at most 200 bytes; control characters escaped.
fn printable(bytes: &[u8]) -> String
{
    let shown = &bytes[..bytes.len().min(200)];
    let mut text = String::new();
    for c in String::from_utf8_lossy(shown).chars()
    {
        if c.is_control()
        {
            text.extend(c.escape_default());
        }
        else
        {
            text.push(c);
        }
    }
    if shown.len() < bytes.len()
    {
        text.push_str("...");
    }
    text
}

fn starts_with_ignore_case(line: &[u8], prefix: &[u8]) -> bool
{
    line.len() >= prefix.len() && line[..prefix.len()].eq_ignore_ascii_case(prefix)
}

/// RFC 5321 section 4.1.3 address literal.
pub fn address_literal(address: SocketAddr) -> String
{
    match address
    {
        SocketAddr::V4(v4) => format!("[{}]", v4.ip()),
        SocketAddr::V6(v6) => format!("[IPv6:{}]", v6.ip()),
    }
}

struct Session<'a, S>
{
    reader: BufReader<&'a mut S>,
    received: u64,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Session<'_, S>
{
    async fn send(&mut self, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>>
    {
        let stream = self.reader.get_mut();
        stream.write_all(bytes).await?;
        stream.flush().await?;
        Ok(())
    }

    /// One line without its CRLF or LF terminator.
    async fn line(&mut self) -> Result<Vec<u8>, Box<dyn std::error::Error>>
    {
        let mut line = Vec::new();
        let limit = MAX_RECEIVED - self.received;
        let n = (&mut self.reader)
            .take(limit)
            .read_until(b'\n', &mut line)
            .await?;
        self.received += n as u64;
        if line.last() != Some(&b'\n')
        {
            return Err(if self.received >= MAX_RECEIVED
            {
                Error::protocol("STARTTLS negotiation exceeds 64 KiB")
            }
            else
            {
                Error::protocol("connection closed during STARTTLS negotiation")
            }
            .into());
        }
        line.pop();
        if line.last() == Some(&b'\r')
        {
            line.pop();
        }
        Ok(line)
    }

    /// RFC 959/5321 reply: `ddd-` continues, `ddd` followed by SP or end of line is final.
    async fn reply(
        &mut self,
        command: &str,
        accept: &[&[u8; 3]],
    ) -> Result<(), Box<dyn std::error::Error>>
    {
        let first = self.line().await?;
        let code = match first.get(..3)
        {
            Some(code) if code.iter().all(u8::is_ascii_digit) => code.to_vec(),
            _ =>
            {
                return Err(Error::protocol(format!(
                    "{command}: malformed reply: {}",
                    printable(&first)
                ))
                .into());
            }
        };
        let mut last = first;
        let mut done = last.get(3) != Some(&b'-');
        while !done
        {
            last = self.line().await?;
            done = last.starts_with(&code) && last.get(3) != Some(&b'-');
        }
        if accept.iter().any(|accepted| code == accepted[..])
        {
            Ok(())
        }
        else
        {
            Err(Error::rejected(command, &last).into())
        }
    }

    /// ManageSieve (RFC 5804) response: lines until OK, NO, or BYE.
    async fn sieve_response(&mut self, command: &str) -> Result<(), Box<dyn std::error::Error>>
    {
        loop
        {
            let line = self.line().await?;
            let word = line.split(|byte| *byte == b' ').next().unwrap_or_default();
            if word.eq_ignore_ascii_case(b"OK")
            {
                return Ok(());
            }
            if word.eq_ignore_ascii_case(b"NO") || word.eq_ignore_ascii_case(b"BYE")
            {
                return Err(Error::rejected(command, &line).into());
            }
        }
    }
}

/// Runs the plaintext exchange up to the TLS handshake. Bytes are excluded from session counts.
pub async fn negotiate<S: AsyncRead + AsyncWrite + Unpin>(
    protocol: Protocol,
    stream: &mut S,
    hello_name: &str,
) -> Result<(), Box<dyn std::error::Error>>
{
    let mut session = Session {
        reader: BufReader::new(stream),
        received: 0,
    };
    match protocol
    {
        Protocol::Smtp | Protocol::Lmtp =>
        {
            let hello = if protocol == Protocol::Smtp
            {
                "EHLO"
            }
            else
            {
                "LHLO"
            };
            session.reply("greeting", &[b"220"]).await?;
            session
                .send(format!("{hello} {hello_name}\r\n").as_bytes())
                .await?;
            session.reply(hello, &[b"250"]).await?;
            session.send(b"STARTTLS\r\n").await?;
            session.reply("STARTTLS", &[b"220"]).await?;
        }
        Protocol::Ftp =>
        {
            session.reply("greeting", &[b"220"]).await?;
            session.send(b"AUTH TLS\r\n").await?;
            session.reply("AUTH TLS", &[b"234"]).await?;
        }
        Protocol::Nntp =>
        {
            session.reply("greeting", &[b"200", b"201"]).await?;
            session.send(b"STARTTLS\r\n").await?;
            session.reply("STARTTLS", &[b"382"]).await?;
        }
        Protocol::Pop3 =>
        {
            for command in ["greeting", "STLS"]
            {
                if command == "STLS"
                {
                    session.send(b"STLS\r\n").await?;
                }
                let line = session.line().await?;
                if !starts_with_ignore_case(&line, b"+OK")
                {
                    return Err(Error::rejected(command, &line).into());
                }
            }
        }
        Protocol::Imap =>
        {
            let greeting = session.line().await?;
            if !starts_with_ignore_case(&greeting, b"* OK")
            {
                return Err(Error::rejected("greeting", &greeting).into());
            }
            session.send(b"a1 STARTTLS\r\n").await?;
            loop
            {
                let line = session.line().await?;
                if starts_with_ignore_case(&line, b"a1 OK")
                {
                    break;
                }
                if starts_with_ignore_case(&line, b"a1 ")
                    || starts_with_ignore_case(&line, b"* BYE")
                {
                    return Err(Error::rejected("STARTTLS", &line).into());
                }
                if !line.starts_with(b"* ")
                {
                    return Err(Error::protocol(format!(
                        "STARTTLS: unexpected response: {}",
                        printable(&line)
                    ))
                    .into());
                }
            }
        }
        Protocol::Sieve =>
        {
            session.sieve_response("greeting").await?;
            session.send(b"STARTTLS\r\n").await?;
            session.sieve_response("STARTTLS").await?;
        }
        Protocol::Postgres =>
        {
            session.send(&POSTGRES_SSL_REQUEST).await?;
            let mut answer = [0u8; 1];
            if session.reader.read(&mut answer).await? == 0
            {
                return Err(Error::protocol("connection closed during STARTTLS negotiation").into());
            }
            if answer[0] != b'S'
            {
                return Err(Error::rejected("SSLRequest", &answer).into());
            }
        }
    }
    let unread = session.reader.buffer().len();
    if unread > 0
    {
        return Err(Error::new(
            "starttls_unexpected_data",
            format!("server sent {unread} plaintext bytes after the STARTTLS reply"),
        )
        .into());
    }
    Ok(())
}
