use std::env;
use std::error::Error;
use std::io::IsTerminal;
use std::process::ExitCode;
use std::time::Duration;

use tokio::io::{self, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;

trait StreamLike: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> StreamLike for T {}
type DynStream = Box<dyn StreamLike>;

const EXIT_ERROR: u8 = 1;
const EXIT_USAGE: u8 = 2;
const EXIT_EXPECT_FAILED: u8 = 3;

#[derive(Debug)]
struct Config {
    host: String,
    port: u16,
    tls: bool,
    insecure: bool,
    commands: Vec<String>,
    expect: Option<String>,
    idle_timeout: Option<Duration>,
    connect_timeout: Duration,
    eol: &'static [u8],
    raw: bool,
    quiet: bool,
}

fn print_usage() {
    eprintln!(
        "Usage: telnetz <host> <port> [options]\n\
         \n\
         Options:\n\
           --tls                  Use TLS for the connection.\n\
           --insecure             Skip certificate validation (TLS only).\n\
           -c, --command <LINE>   Send LINE (repeatable); stdin is not read.\n\
           --expect <TEXT>        Exit 0 as soon as TEXT appears in the output,\n\
                                  exit 3 if the connection ends without it.\n\
           -w, --timeout <SECS>   Exit after SECS without traffic.\n\
           --connect-timeout <SECS>  Connect/handshake timeout (default 10).\n\
           --lf                   Terminate lines with LF instead of CRLF.\n\
           --raw                  Forward stdin bytes unchanged.\n\
           -q, --quiet            No status messages on stderr.\n\
           -h, --help             Show this help.\n\
         \n\
         If stdin is a terminal, lines are read interactively; /quit or /exit\n\
         ends the session. Otherwise stdin (or -c) is sent and output is read\n\
         until the remote closes, --expect matches or -w expires.\n\
         \n\
         Exit codes: 0 ok, 1 connection/IO error, 2 usage error,\n\
         3 --expect text not seen.\n"
    );
}

fn parse_secs(flag: &str, value: &str) -> Result<Duration, Box<dyn Error>> {
    value
        .parse::<f64>()
        .ok()
        .and_then(|s| Duration::try_from_secs_f64(s).ok())
        .ok_or_else(|| format!("{flag}: invalid seconds '{value}'").into())
}

fn parse_args() -> Result<Config, Box<dyn Error>> {
    let mut host: Option<String> = None;
    let mut port: Option<u16> = None;
    let mut tls = false;
    let mut insecure = false;
    let mut commands = Vec::new();
    let mut expect = None;
    let mut idle_timeout = None;
    let mut connect_timeout = Duration::from_secs(10);
    let mut eol: &'static [u8] = b"\r\n";
    let mut raw = false;
    let mut quiet = false;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = |flag: &str| args.next().ok_or_else(|| format!("{flag} requires a value"));
        match arg.as_str() {
            "--tls" => tls = true,
            "--insecure" => insecure = true,
            "-c" | "--command" => commands.push(value(&arg)?),
            "--expect" => expect = Some(value(&arg)?).filter(|s| !s.is_empty()),
            "-w" | "--timeout" => idle_timeout = Some(parse_secs(&arg, &value(&arg)?)?),
            "--connect-timeout" => connect_timeout = parse_secs(&arg, &value(&arg)?)?,
            "--lf" => eol = b"\n",
            "--raw" => raw = true,
            "-q" | "--quiet" => quiet = true,
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            _ if arg.starts_with('-') && arg.len() > 1 => {
                return Err(format!("Unknown option: {arg}").into());
            }
            _ => {
                if host.is_none() {
                    host = Some(arg);
                } else if port.is_none() {
                    port = Some(arg.parse().map_err(|_| format!("Invalid port: {arg}"))?);
                } else {
                    return Err(format!("Unexpected argument: {arg}").into());
                }
            }
        }
    }

    let host = host.ok_or("Missing host")?;
    let port = port.ok_or("Missing port")?;

    if insecure && !tls {
        return Err("--insecure requires --tls".into());
    }

    Ok(Config {
        host,
        port,
        tls,
        insecure,
        commands,
        expect,
        idle_timeout,
        connect_timeout,
        eol,
        raw,
        quiet,
    })
}

async fn connect(config: &Config) -> Result<DynStream, Box<dyn Error>> {
    let stream = TcpStream::connect((config.host.as_str(), config.port)).await?;

    if !config.tls {
        return Ok(Box::new(stream));
    }

    let client_config = if config.insecure {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(NoVerifier::new())
            .with_no_client_auth()
    } else {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    let connector = TlsConnector::from(std::sync::Arc::new(client_config));
    let server_name = rustls::pki_types::ServerName::try_from(config.host.clone())
        .map_err(|_| "Invalid DNS name for TLS")?;
    let tls_stream = connector.connect(server_name, stream).await?;

    Ok(Box::new(tls_stream))
}

#[derive(Debug)]
struct NoVerifier(std::sync::Arc<rustls::crypto::CryptoProvider>);

impl NoVerifier {
    fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self(std::sync::Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        )))
    }
}

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Sends `-c` lines, then closes the channel.
fn spawn_commands(config: &Config, tx: mpsc::UnboundedSender<Vec<u8>>) {
    for cmd in &config.commands {
        let mut line = cmd.clone().into_bytes();
        line.extend_from_slice(config.eol);
        let _ = tx.send(line);
    }
}

/// Reads piped stdin; lines are re-terminated with `eol` unless `raw`.
fn spawn_stdin(raw: bool, eol: &'static [u8], tx: mpsc::UnboundedSender<Vec<u8>>) {
    tokio::spawn(async move {
        let mut stdin = io::BufReader::new(io::stdin());
        let mut buf = Vec::new();
        loop {
            buf.clear();
            let n = if raw {
                buf.resize(4096, 0);
                let n = stdin.read(&mut buf).await.unwrap_or(0);
                buf.truncate(n);
                n
            } else {
                stdin.read_until(b'\n', &mut buf).await.unwrap_or(0)
            };
            if n == 0 {
                break;
            }
            if !raw {
                if buf.last() == Some(&b'\n') {
                    buf.pop();
                }
                if buf.last() == Some(&b'\r') {
                    buf.pop();
                }
                buf.extend_from_slice(eol);
            }
            if tx.send(buf.clone()).is_err() {
                break;
            }
        }
    });
}

/// Interactive rustyline input; the channel closes on /quit, /exit or EOF.
fn spawn_readline(eol: &'static [u8], tx: mpsc::UnboundedSender<Vec<u8>>) {
    tokio::task::spawn_blocking(move || {
        let mut rl = rustyline::Editor::<(), rustyline::history::DefaultHistory>::new()
            .expect("failed to initialize rustyline");
        loop {
            match rl.readline("") {
                Ok(line) => {
                    if line == "/quit" || line == "/exit" {
                        break;
                    }
                    let mut bytes = line.into_bytes();
                    bytes.extend_from_slice(eol);
                    if tx.send(bytes).is_err() {
                        break;
                    }
                }
                Err(rustyline::error::ReadlineError::Interrupted) => continue,
                Err(rustyline::error::ReadlineError::Eof) => break,
                Err(err) => {
                    eprintln!("Readline error: {err}");
                    break;
                }
            }
        }
    });
}

/// Substring search across read chunks; keeps the last `pattern.len() - 1` bytes.
struct Matcher {
    pattern: Vec<u8>,
    window: Vec<u8>,
}

impl Matcher {
    fn feed(&mut self, chunk: &[u8]) -> bool {
        self.window.extend_from_slice(chunk);
        if self.window.windows(self.pattern.len()).any(|w| w == self.pattern) {
            return true;
        }
        let keep = self.pattern.len() - 1;
        if self.window.len() > keep {
            self.window.drain(..self.window.len() - keep);
        }
        false
    }
}

async fn run(config: Config) -> Result<u8, Box<dyn Error>> {
    let stream = tokio::time::timeout(config.connect_timeout, connect(&config))
        .await
        .map_err(|_| format!("connect to {}:{} timed out", config.host, config.port))??;
    let (read_half, mut write_half) = io::split(stream);
    let mut socket_reader = io::BufReader::new(read_half);
    let mut socket_buf = vec![0u8; 8192];

    let interactive = config.commands.is_empty() && std::io::stdin().is_terminal();
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    if !config.commands.is_empty() {
        spawn_commands(&config, tx);
    } else if interactive {
        spawn_readline(config.eol, tx);
    } else {
        spawn_stdin(config.raw, config.eol, tx);
    }

    let mut matcher = config.expect.as_ref().map(|p| Matcher {
        pattern: p.clone().into_bytes(),
        window: Vec::new(),
    });

    if !config.quiet {
        if interactive {
            eprintln!(
                "Connected to {}:{} (tls: {}). Type /quit to exit.",
                config.host, config.port, config.tls
            );
        } else {
            eprintln!("Connected to {}:{} (tls: {}).", config.host, config.port, config.tls);
        }
    }

    let mut stdout = io::stdout();
    let mut input_open = true;
    loop {
        let idle = async {
            match config.idle_timeout {
                Some(d) => tokio::time::sleep(d).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            result = socket_reader.read(&mut socket_buf) => {
                let n = result?;
                if n == 0 {
                    if !config.quiet {
                        eprintln!("\nConnection closed by remote.");
                    }
                    break;
                }
                stdout.write_all(&socket_buf[..n]).await?;
                stdout.flush().await?;
                if matcher.as_mut().is_some_and(|m| m.feed(&socket_buf[..n])) {
                    let _ = write_half.shutdown().await;
                    return Ok(0);
                }
            }
            msg = rx.recv(), if input_open => match msg {
                Some(bytes) => {
                    write_half.write_all(&bytes).await?;
                    write_half.flush().await?;
                }
                None if interactive => break,
                None => input_open = false,
            },
            _ = idle => {
                if !config.quiet {
                    eprintln!("\nIdle timeout.");
                }
                break;
            }
        }
    }

    let _ = write_half.shutdown().await;
    Ok(if matcher.is_some() { EXIT_EXPECT_FAILED } else { 0 })
}

#[tokio::main]
async fn main() -> ExitCode {
    let config = match parse_args() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("Error: {err}");
            print_usage();
            return ExitCode::from(EXIT_USAGE);
        }
    };

    match run(config).await {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            eprintln!("Error: {err}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}
