use std::env;
use std::error::Error;
use std::net::ToSocketAddrs;

use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;

trait StreamLike: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> StreamLike for T {}
type DynStream = Box<dyn StreamLike>;

#[derive(Debug)]
struct Config {
    host: String,
    port: u16,
    tls: bool,
    insecure: bool,
}

fn print_usage() {
    eprintln!(
        "Usage: telnetz <host> <port> [--tls] [--insecure]\n\
         \n\
         Options:\n\
           --tls        Use TLS for the connection.\n\
           --insecure   Skip certificate validation (TLS only).\n\
           -h, --help   Show this help.\n\
         \n\
         Commands:\n\
           /quit, /exit Exit the session.\n"
    );
}

fn parse_args() -> Result<Config, Box<dyn Error>> {
    let mut host: Option<String> = None;
    let mut port: Option<u16> = None;
    let mut tls = false;
    let mut insecure = false;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--tls" => tls = true,
            "--insecure" => insecure = true,
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            _ => {
                if host.is_none() {
                    host = Some(arg);
                } else if port.is_none() {
                    port = Some(arg.parse()?);
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
    })
}

async fn connect(config: &Config) -> Result<DynStream, Box<dyn Error>> {
    let addr = (config.host.as_str(), config.port)
        .to_socket_addrs()?
        .next()
        .ok_or("Unable to resolve host")?;
    let stream = TcpStream::connect(addr).await?;

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let config = match parse_args() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("Error: {err}");
            print_usage();
            return Ok(());
        }
    };

    let stream = connect(&config).await?;
    let (read_half, mut write_half) = io::split(stream);

    let mut socket_reader = io::BufReader::new(read_half);
    let mut socket_buf = vec![0u8; 2048];
    let (line_tx, mut line_rx) = mpsc::unbounded_channel::<String>();

    tokio::task::spawn_blocking(move || {
        let mut rl = rustyline::Editor::<(), rustyline::history::DefaultHistory>::new()
            .expect("failed to initialize rustyline");
        loop {
            match rl.readline("") {
                Ok(line) => {
                    if line_tx.send(line).is_err() {
                        break;
                    }
                }
                Err(rustyline::error::ReadlineError::Interrupted) => {
                    continue;
                }
                Err(rustyline::error::ReadlineError::Eof) => {
                    break;
                }
                Err(err) => {
                    eprintln!("Readline error: {err}");
                    break;
                }
            }
        }
    });
    let mut stdout = io::stdout();

    eprintln!(
        "Connected to {}:{} (tls: {}). Type /quit to exit.",
        config.host, config.port, config.tls
    );

    loop {
        tokio::select! {
            result = socket_reader.read(&mut socket_buf) => {
                let n = result?;
                if n == 0 {
                    eprintln!("\nConnection closed by remote.");
                    break;
                }
                stdout.write_all(&socket_buf[..n]).await?;
                stdout.flush().await?;
            }
            line = line_rx.recv() => {
                match line {
                    Some(line) => {
                        if line == "/quit" || line == "/exit" {
                            break;
                        }
                        write_half.write_all(line.as_bytes()).await?;
                        write_half.write_all(b"\r\n").await?;
                        write_half.flush().await?;
                    }
                    None => break,
                }
            }
        }
    }

    write_half.shutdown().await?;
    Ok(())
}
