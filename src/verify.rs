use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{VerifierBuilderError, WebPkiServerVerifier, verify_server_name};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, Error, RootCertStore, SignatureScheme};
use x509_cert::Certificate;
use x509_cert::der::{Decode, asn1::ObjectIdentifier};
use x509_cert::ext::pkix::ExtendedKeyUsage;

#[derive(Debug)]
pub struct ImportedCertificateVerifier
{
    inner: Arc<WebPkiServerVerifier>,
    imported: Vec<CertificateDer<'static>>,
}

impl ImportedCertificateVerifier
{
    pub fn new(
        roots: RootCertStore,
        imported: Vec<CertificateDer<'static>>,
    ) -> Result<Arc<Self>, VerifierBuilderError>
    {
        Ok(Arc::new(Self {
            inner: WebPkiServerVerifier::builder(Arc::new(roots)).build()?,
            imported,
        }))
    }
}

impl ServerCertVerifier for ImportedCertificateVerifier
{
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error>
    {
        let result = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        );
        let Err(Error::InvalidCertificate(CertificateError::Other(error))) = &result
        else
        {
            return result;
        };
        if error.0.downcast_ref::<webpki::Error>() != Some(&webpki::Error::CaUsedAsEndEntity)
            || !self
                .imported
                .iter()
                .any(|cert| cert.as_ref() == end_entity.as_ref())
        {
            return result;
        }

        // Only the identical imported leaf may bypass webpki's CA role restriction.
        let parsed = rustls::server::ParsedCertificate::try_from(end_entity)?;
        let certificate = Certificate::from_der(end_entity.as_ref())
            .map_err(|_| CertificateError::BadEncoding)?;
        let tbs = certificate.tbs_certificate();
        let not_before = UnixTime::since_unix_epoch(tbs.validity().not_before.to_unix_duration());
        let not_after = UnixTime::since_unix_epoch(tbs.validity().not_after.to_unix_duration());
        if not_before > not_after
        {
            return Err(CertificateError::Expired.into());
        }
        if now < not_before
        {
            return Err(CertificateError::NotValidYetContext {
                time: now,
                not_before,
            }
            .into());
        }
        if now > not_after
        {
            return Err(CertificateError::ExpiredContext {
                time: now,
                not_after,
            }
            .into());
        }
        const SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");
        if let Some((_, usages)) = tbs
            .get_extension::<ExtendedKeyUsage>()
            .map_err(|_| CertificateError::BadEncoding)?
            && !usages.0.contains(&SERVER_AUTH)
        {
            return Err(CertificateError::InvalidPurpose.into());
        }
        verify_server_name(&parsed, server_name)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error>
    {
        self.inner.verify_tls12_signature(message, cert, signature)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error>
    {
        self.inner.verify_tls13_signature(message, cert, signature)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme>
    {
        self.inner.supported_verify_schemes()
    }
}
