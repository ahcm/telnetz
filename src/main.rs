use std::env;
use std::error::Error;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use tokio::io::{self, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;

mod report;
mod tls_info;
use report::Report;

trait StreamLike: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> StreamLike for T {}
type DynStream = Box<dyn StreamLike>;

const EXIT_ERROR: u8 = 1;
const EXIT_USAGE: u8 = 2;
const EXIT_EXPECT_FAILED: u8 = 3;
const EXIT_LIMIT: u8 = 4;

#[derive(Debug)]
struct Config {
    host: String,
    port: u16,
    tls: bool,
    server_name: Option<String>,
    insecure: bool,
    no_default_ca: bool,
    ca_certs: Vec<PathBuf>,
    dump_cert: Option<PathBuf>,
    tls_info: bool,
    commands: Vec<String>,
    expect: Option<String>,
    idle_timeout: Option<Duration>,
    connect_timeout: Duration,
    max_time: Option<Duration>,
    max_bytes: Option<u64>,
    eol: &'static [u8],
    raw: bool,
    shutdown_write: bool,
    quiet: bool,
    json: bool,
}

fn print_usage() {
    eprintln!(
        "Usage: telnetz <host> <port> [options]\n\
         \n\
         Options:\n\
           --tls                  Use TLS for the connection.\n\
           --server-name <NAME>   Override TLS SNI and certificate hostname.\n\
           --insecure             Skip certificate validation (TLS only).\n\
           --no-default-ca        Ignore bundled CA certificates (TLS only).\n\
           --cacert <FILE>        Trust extra PEM/DER certificates (TLS only;\n\
                                  repeatable).\n\
           --dump-cert <FILE>     Save unverified server PEM and exit (TLS only).\n\
                                  Use - for stdout; existing files are preserved.\n\
           --tls-info             Inspect TLS and certificates, then exit.\n\
           -c, --command <LINE>   Send LINE (repeatable); stdin is not read.\n\
           --expect <TEXT>        Exit 0 as soon as TEXT appears in the output,\n\
                                  exit 3 if the connection ends without it.\n\
           -w, --timeout <SECS>   Exit after SECS without traffic.\n\
           --connect-timeout <SECS>  Connect/handshake timeout (default 10).\n\
           --max-time <SECS>      Limit total connection/session time.\n\
           --max-bytes <BYTES>    Limit received application bytes (positive).\n\
           --lf                   Terminate lines with LF instead of CRLF.\n\
           --raw                  Forward stdin bytes unchanged.\n\
           --shutdown-write       Signal EOF after input; keep reading replies.\n\
           -q, --quiet            No status messages on stderr.\n\
           --json                 Emit one JSON result (default byte cap 1 MiB).\n\
           -h, --help             Show this help.\n\
         \n\
         If stdin is a terminal, lines are read interactively; /quit or /exit\n\
         ends the session. Otherwise stdin (or -c) is sent and output is read\n\
         until the remote closes, --expect matches or -w expires.\n\
         \n\
         Exit codes: 0 ok, 1 connection/IO error, 2 usage error,\n\
         3 --expect text not seen, 4 hard limit reached.\n"
    );
}

fn parse_secs(flag: &str, value: &str) -> Result<Duration, Box<dyn Error>> {
    value
        .parse::<f64>()
        .ok()
        .and_then(|s| Duration::try_from_secs_f64(s).ok())
        .ok_or_else(|| format!("{flag}: invalid seconds '{value}'").into())
}

fn parse_args(arguments: &[String]) -> Result<Config, Box<dyn Error>> {
    let mut host: Option<String> = None;
    let mut port: Option<u16> = None;
    let mut tls = false;
    let mut server_name = None;
    let mut insecure = false;
    let mut no_default_ca = false;
    let mut ca_certs = Vec::new();
    let mut dump_cert = None;
    let mut tls_info = false;
    let mut commands = Vec::new();
    let mut expect = None;
    let mut idle_timeout = None;
    let mut connect_timeout = Duration::from_secs(10);
    let mut max_time = None;
    let mut max_bytes = None;
    let mut eol: &'static [u8] = b"\r\n";
    let mut raw = false;
    let mut shutdown_write = false;
    let mut quiet = false;
    let mut json = false;

    let mut args = arguments.iter().cloned();
    while let Some(arg) = args.next() {
        let mut value = |flag: &str| {
            args.next()
                .ok_or_else(|| format!("{flag} requires a value"))
        };
        match arg.as_str() {
            "--tls" => tls = true,
            "--server-name" => server_name = Some(value(&arg)?),
            "--insecure" => insecure = true,
            "--no-default-ca" => no_default_ca = true,
            "--cacert" => ca_certs.push(PathBuf::from(value(&arg)?)),
            "--dump-cert" => dump_cert = Some(PathBuf::from(value(&arg)?)),
            "--tls-info" => tls_info = true,
            "-c" | "--command" => commands.push(value(&arg)?),
            "--expect" => expect = Some(value(&arg)?).filter(|s| !s.is_empty()),
            "-w" | "--timeout" => idle_timeout = Some(parse_secs(&arg, &value(&arg)?)?),
            "--connect-timeout" => connect_timeout = parse_secs(&arg, &value(&arg)?)?,
            "--max-time" => max_time = Some(parse_secs(&arg, &value(&arg)?)?),
            "--max-bytes" => {
                max_bytes = Some(
                    value(&arg)?
                        .parse::<u64>()
                        .ok()
                        .filter(|n| *n > 0)
                        .ok_or("--max-bytes requires a positive integer")?,
                );
            }
            "--lf" => eol = b"\n",
            "--raw" => raw = true,
            "--shutdown-write" => shutdown_write = true,
            "-q" | "--quiet" => quiet = true,
            "--json" => json = true,
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

    if tls_info {
        if !tls {
            return Err("--tls-info requires --tls".into());
        }
        if dump_cert.is_some() || !commands.is_empty() || expect.is_some() {
            return Err("--tls-info cannot be used with --dump-cert, --command, or --expect".into());
        }
    }
    if let Some(name) = &server_name {
        if !tls {
            return Err("--server-name requires --tls".into());
        }
        rustls::pki_types::ServerName::try_from(name.as_str())
            .map_err(|_| "--server-name requires a valid DNS name or IP address")?;
    }
    if insecure && !tls {
        return Err("--insecure requires --tls".into());
    }
    if no_default_ca && !tls {
        return Err("--no-default-ca requires --tls".into());
    }
    if !ca_certs.is_empty() {
        if !tls {
            return Err("--cacert requires --tls".into());
        }
        if insecure {
            return Err("--cacert cannot be used with --insecure".into());
        }
    }
    if dump_cert.is_some() {
        if !tls {
            return Err("--dump-cert requires --tls".into());
        }
        if !ca_certs.is_empty() || !commands.is_empty() || expect.is_some() {
            return Err("--dump-cert cannot be used with --cacert, --command, or --expect".into());
        }
        if json && dump_cert.as_deref() == Some(Path::new("-")) {
            return Err("--json cannot be used with --dump-cert -".into());
        }
    }

    if json && max_bytes.is_none() {
        max_bytes = Some(1024 * 1024);
    }

    Ok(Config {
        host,
        port,
        tls,
        server_name,
        insecure,
        no_default_ca,
        ca_certs,
        dump_cert,
        tls_info,
        commands,
        expect,
        idle_timeout,
        connect_timeout,
        max_time,
        max_bytes,
        eol,
        raw,
        shutdown_write,
        quiet: quiet || json,
        json,
    })
}

async fn load_ca_certificates(
    root_store: &mut rustls::RootCertStore,
    path: &Path,
) -> Result<(), Box<dyn Error>> {
    let contents = tokio::fs::read(path)
        .await
        .map_err(|err| format!("Cannot read certificate file {}: {err}", path.display()))?;
    let mut certs = CertificateDer::pem_slice_iter(&contents)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("Invalid certificate file {}: {err}", path.display()))?;
    if certs.is_empty() {
        certs.push(CertificateDer::from(contents));
    }
    for cert in certs {
        root_store
            .add(cert)
            .map_err(|err| format!("Invalid certificate in {}: {err}", path.display()))?;
    }
    Ok(())
}

async fn connect_tls(
    config: &Config,
    report: &mut Report,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, Box<dyn Error>> {
    report.phase = "certificate";
    let client_config = if config.insecure || config.dump_cert.is_some() {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(NoVerifier::new())
            .with_no_client_auth()
    } else {
        let mut root_store = rustls::RootCertStore::empty();
        if !config.no_default_ca {
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        for path in &config.ca_certs {
            load_ca_certificates(&mut root_store, path).await?;
        }
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    let connector = TlsConnector::from(std::sync::Arc::new(client_config));
    let effective_name = config.server_name.as_ref().unwrap_or(&config.host);
    report.server_name = Some(effective_name.clone());
    let server_name = rustls::pki_types::ServerName::try_from(effective_name.clone())
        .map_err(|_| "Invalid DNS name for TLS")?;
    let stream = connect_tcp(config, report).await?;
    report.phase = "tls";
    let stream = connector.connect(server_name, stream).await?;
    if config.json || config.tls_info {
        report.tls = Some(tls_info::inspect(
            stream.get_ref().1,
            !config.insecure && config.dump_cert.is_none(),
        ));
    }
    Ok(stream)
}

async fn connect_tcp(config: &Config, report: &mut Report) -> Result<TcpStream, Box<dyn Error>> {
    report.phase = "dns";
    let addresses: Vec<_> = tokio::net::lookup_host((config.host.as_str(), config.port))
        .await?
        .collect();
    report.phase = "connect";
    let stream = TcpStream::connect(addresses.as_slice()).await?;
    report.peer_addr = Some(stream.peer_addr()?.to_string());
    Ok(stream)
}

async fn connect(config: &Config, report: &mut Report) -> Result<DynStream, Box<dyn Error>> {
    if config.tls {
        Ok(Box::new(connect_tls(config, report).await?))
    } else {
        Ok(Box::new(connect_tcp(config, report).await?))
    }
}

async fn dump_certificate(
    config: &Config,
    path: &Path,
    report: &mut Report,
) -> Result<u8, Box<dyn Error>> {
    let mut stream = tokio::time::timeout(config.connect_timeout, connect_tls(config, report))
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "connect/handshake timed out")
        })??;
    let certificate = stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certs| certs.first())
        .ok_or("Server did not provide a certificate")?;
    let encoded = STANDARD.encode(certificate.as_ref());
    let mut pem = b"-----BEGIN CERTIFICATE-----\n".to_vec();
    for line in encoded.as_bytes().chunks(64) {
        pem.extend_from_slice(line);
        pem.push(b'\n');
    }
    pem.extend_from_slice(b"-----END CERTIFICATE-----\n");
    let _ = stream.shutdown().await;

    report.phase = "output";
    let write_result = async {
        let mut output: Box<dyn AsyncWrite + Unpin> = if path == Path::new("-") {
            Box::new(io::stdout())
        } else {
            Box::new(
                tokio::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)
                    .await?,
            )
        };
        output.write_all(&pem).await?;
        output.flush().await
    }
    .await;
    write_result.map_err(|err| format!("Cannot write certificate to {}: {err}", path.display()))?;
    if !config.quiet {
        eprintln!("Saved unverified server certificate to {}.", path.display());
    }
    Ok(report.finish(0, "certificate_dumped"))
}

async fn inspect_tls(config: &Config, report: &mut Report) -> Result<u8, Box<dyn Error>> {
    let mut stream = tokio::time::timeout(config.connect_timeout, connect_tls(config, report))
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "connect/handshake timed out")
        })??;
    let _ = stream.shutdown().await;
    if !config.json {
        report.phase = "output";
        let mut bytes = serde_json::to_vec_pretty(&report.tls)?;
        bytes.push(b'\n');
        let mut output = io::stdout();
        output.write_all(&bytes).await?;
        output.flush().await?;
    }
    Ok(report.finish(0, "tls_info"))
}

#[derive(Debug)]
struct NoVerifier(std::sync::Arc<rustls::crypto::CryptoProvider>);

impl NoVerifier {
    fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self(
            std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        ))
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
        if self
            .window
            .windows(self.pattern.len())
            .any(|w| w == self.pattern)
        {
            return true;
        }
        let keep = self.pattern.len() - 1;
        if self.window.len() > keep {
            self.window.drain(..self.window.len() - keep);
        }
        false
    }
}

async fn run(config: &Config, report: &mut Report) -> Result<u8, Box<dyn Error>> {
    if config.tls_info {
        return inspect_tls(config, report).await;
    }
    if let Some(path) = &config.dump_cert {
        return dump_certificate(config, path, report).await;
    }
    let stream = tokio::time::timeout(config.connect_timeout, connect(config, report))
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "connect/handshake timed out")
        })??;
    let (read_half, mut write_half) = io::split(stream);
    let mut socket_reader = io::BufReader::new(read_half);
    let mut socket_buf = vec![0u8; 8192];

    let interactive = !config.json && config.commands.is_empty() && std::io::stdin().is_terminal();
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    if !config.commands.is_empty() {
        spawn_commands(config, tx);
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
        report.phase = "read";
        let read_size = config.max_bytes.map_or(socket_buf.len(), |limit| {
            (limit - report.bytes_received).min(socket_buf.len() as u64) as usize
        });
        let idle = async {
            match config.idle_timeout {
                Some(d) => tokio::time::sleep(d).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            result = socket_reader.read(&mut socket_buf[..read_size]) => {
                let n = result?;
                if n == 0 {
                    if !config.quiet {
                        eprintln!("\nConnection closed by remote.");
                    }
                    report.reason = "eof";
                    break;
                }
                report.bytes_received += n as u64;
                if config.json {
                    report.output.extend_from_slice(&socket_buf[..n]);
                } else {
                    report.phase = "output";
                    stdout.write_all(&socket_buf[..n]).await?;
                    stdout.flush().await?;
                    report.phase = "read";
                }
                if matcher.as_mut().is_some_and(|m| m.feed(&socket_buf[..n])) {
                    report.matched = true;
                    report.finish(0, "expect_matched");
                    let _ = write_half.shutdown().await;
                    return Ok(0);
                }
                if config.max_bytes.is_some_and(|limit| report.bytes_received >= limit) {
                    if !config.quiet {
                        eprintln!("\nReceive byte limit reached.");
                    }
                    return Ok(report.finish(EXIT_LIMIT, "max_bytes"));
                }
            }
            msg = rx.recv(), if input_open => match msg {
                Some(bytes) => {
                    report.phase = "write";
                    let mut remaining = bytes.as_slice();
                    while !remaining.is_empty() {
                        let n = write_half.write(remaining).await?;
                        if n == 0 {
                            return Err(std::io::Error::from(std::io::ErrorKind::WriteZero).into());
                        }
                        report.bytes_sent += n as u64;
                        remaining = &remaining[n..];
                    }
                    write_half.flush().await?;
                }
                None if interactive => {
                    report.reason = "input_closed";
                    break;
                },
                None => {
                    input_open = false;
                    if config.shutdown_write {
                        report.phase = "write";
                        write_half.shutdown().await?;
                    }
                },
            },
            _ = idle => {
                if !config.quiet {
                    eprintln!("\nIdle timeout.");
                }
                report.reason = "idle_timeout";
                break;
            }
        }
    }

    let _ = write_half.shutdown().await;
    let code = if matcher.is_some() {
        EXIT_EXPECT_FAILED
    } else {
        0
    };
    Ok(report.finish(code, report.reason))
}

fn json_requested(arguments: &[String]) -> bool {
    let mut args = arguments.iter();
    while let Some(arg) = args.next() {
        if arg == "--json" {
            return true;
        }
        if matches!(
            arg.as_str(),
            "--cacert"
                | "--dump-cert"
                | "-c"
                | "--command"
                | "--expect"
                | "-w"
                | "--timeout"
                | "--connect-timeout"
                | "--max-time"
                | "--max-bytes"
                | "--server-name"
        ) {
            args.next();
        }
    }
    false
}

async fn emit_report(report: &Report) -> Result<(), Box<dyn Error>> {
    let mut bytes = serde_json::to_vec(&report.json())?;
    bytes.push(b'\n');
    let mut output = io::stdout();
    output.write_all(&bytes).await?;
    output.flush().await?;
    Ok(())
}

async fn async_main() -> ExitCode {
    let arguments: Vec<_> = env::args().skip(1).collect();
    let mut report = Report::new();
    let config = match parse_args(&arguments) {
        Ok(config) => config,
        Err(err) => {
            if json_requested(&arguments) {
                report.error = Some(err.to_string());
                if let Err(err) = emit_report(&report).await {
                    eprintln!("Error: {err}");
                }
            } else {
                eprintln!("Error: {err}");
                print_usage();
            }
            return ExitCode::from(EXIT_USAGE);
        }
    };

    let result = match config.max_time {
        Some(limit) => match tokio::time::timeout(limit, run(&config, &mut report)).await {
            Ok(result) => result,
            Err(_) => {
                if !config.quiet {
                    eprintln!("Total time limit reached.");
                }
                Ok(report.finish(EXIT_LIMIT, "max_time"))
            }
        },
        None => run(&config, &mut report).await,
    };
    let code = match result {
        Ok(code) => code,
        Err(err) => {
            report.fail(err.as_ref());
            if !config.json {
                eprintln!("Error: {err}");
            }
            EXIT_ERROR
        }
    };
    if config.json {
        let emitted = match config.max_time {
            Some(limit) => {
                match tokio::time::timeout(report.output_budget(limit), emit_report(&report)).await
                {
                    Ok(result) => result,
                    Err(_) => return ExitCode::from(EXIT_LIMIT),
                }
            }
            None => emit_report(&report).await,
        };
        if let Err(err) = emitted {
            eprintln!("Error: {err}");
            return ExitCode::from(EXIT_ERROR);
        }
    }
    ExitCode::from(code)
}

fn main() -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("Error: {err}");
            return ExitCode::from(EXIT_ERROR);
        }
    };
    let result = runtime.block_on(async_main());
    // stdin and rustyline may have outstanding blocking reads at the deadline.
    runtime.shutdown_background();
    result
}
