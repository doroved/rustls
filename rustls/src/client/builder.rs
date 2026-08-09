use alloc::vec::Vec;
use core::marker::PhantomData;

use pki_types::{CertificateDer, PrivateKeyDer};

use super::client_conn::Resumption;
use crate::builder::{ConfigBuilder, WantsVerifier};
use crate::client::{ClientConfig, EchMode, ResolvesClientCert, handy};
use crate::error::Error;
use crate::key_log::NoKeyLog;
use crate::sign::{CertifiedKey, SingleCertAndKey};
use crate::sync::Arc;
use crate::versions::TLS13;
use crate::webpki::{self, WebPkiServerVerifier};
use crate::{WantsVersions, compress, verify, versions};

impl ConfigBuilder<ClientConfig, WantsVersions> {
    /// Enable Encrypted Client Hello (ECH) in the given mode.
    ///
    /// This implicitly selects TLS 1.3 as the only supported protocol version to meet the
    /// requirement to support ECH.
    ///
    /// The `ClientConfig` that will be produced by this builder will be specific to the provided
    /// [`crate::client::EchConfig`] and may not be appropriate for all connections made by the program.
    /// In this case the configuration should only be shared by connections intended for domains
    /// that offer the provided [`crate::client::EchConfig`] in their DNS zone.
    pub fn with_ech(
        self,
        mode: EchMode,
    ) -> Result<ConfigBuilder<ClientConfig, WantsVerifier>, Error> {
        let mut res = self.with_protocol_versions(&[&TLS13][..])?;
        res.state.client_ech_mode = Some(mode);
        Ok(res)
    }
}

impl ConfigBuilder<ClientConfig, WantsVerifier> {
    /// Choose how to verify server certificates.
    ///
    /// Using this function does not configure revocation.  If you wish to
    /// configure revocation, instead use:
    ///
    /// ```diff
    /// - .with_root_certificates(root_store)
    /// + .with_webpki_verifier(
    /// +   WebPkiServerVerifier::builder_with_provider(root_store, crypto_provider)
    /// +   .with_crls(...)
    /// +   .build()?
    /// + )
    /// ```
    pub fn with_root_certificates(
        self,
        root_store: impl Into<Arc<webpki::RootCertStore>>,
    ) -> ConfigBuilder<ClientConfig, WantsClientCert> {
        let algorithms = self
            .provider
            .signature_verification_algorithms;
        self.with_webpki_verifier(
            WebPkiServerVerifier::new_without_revocation(root_store, algorithms).into(),
        )
    }

    /// Choose how to verify server certificates using a webpki verifier.
    ///
    /// See [`webpki::WebPkiServerVerifier::builder`] and
    /// [`webpki::WebPkiServerVerifier::builder_with_provider`] for more information.
    pub fn with_webpki_verifier(
        self,
        verifier: Arc<WebPkiServerVerifier>,
    ) -> ConfigBuilder<ClientConfig, WantsClientCert> {
        ConfigBuilder {
            state: WantsClientCert {
                versions: self.state.versions,
                verifier,
                client_ech_mode: self.state.client_ech_mode,
                fingerprint: None,
                cert_compressors: None,
                cert_decompressors: None,
            },
            provider: self.provider,
            time_provider: self.time_provider,
            side: PhantomData,
        }
    }

    /// Access configuration options whose use is dangerous and requires
    /// extra care.
    pub fn dangerous(self) -> danger::DangerousClientConfigBuilder {
        danger::DangerousClientConfigBuilder { cfg: self }
    }
}

/// Container for unsafe APIs
pub(super) mod danger {
    use core::marker::PhantomData;

    use crate::client::WantsClientCert;
    use crate::sync::Arc;
    use crate::{ClientConfig, ConfigBuilder, WantsVerifier, verify};

    /// Accessor for dangerous configuration options.
    #[derive(Debug)]
    pub struct DangerousClientConfigBuilder {
        /// The underlying ClientConfigBuilder
        pub cfg: ConfigBuilder<ClientConfig, WantsVerifier>,
    }

    impl DangerousClientConfigBuilder {
        /// Set a custom certificate verifier.
        pub fn with_custom_certificate_verifier(
            self,
            verifier: Arc<dyn verify::ServerCertVerifier>,
        ) -> ConfigBuilder<ClientConfig, WantsClientCert> {
            ConfigBuilder {
                state: WantsClientCert {
                    versions: self.cfg.state.versions,
                    verifier,
                    client_ech_mode: self.cfg.state.client_ech_mode,
                    fingerprint: None,
                    cert_compressors: None,
                    cert_decompressors: None,
                },
                provider: self.cfg.provider,
                time_provider: self.cfg.time_provider,
                side: PhantomData,
            }
        }
    }
}

/// A config builder state where the caller needs to supply whether and how to provide a client
/// certificate.
///
/// For more information, see the [`ConfigBuilder`] documentation.
#[derive(Clone)]
pub struct WantsClientCert {
    versions: versions::EnabledVersions,
    verifier: Arc<dyn verify::ServerCertVerifier>,
    client_ech_mode: Option<EchMode>,
    fingerprint: Option<Arc<dyn crate::client::fingerprint::ClientHelloFingerprinter>>,
    cert_compressors: Option<Vec<&'static dyn compress::CertCompressor>>,
    cert_decompressors: Option<Vec<&'static dyn compress::CertDecompressor>>,
}

impl ConfigBuilder<ClientConfig, WantsClientCert> {
    /// Sets a single certificate chain and matching private key for use
    /// in client authentication.
    ///
    /// `cert_chain` is a vector of DER-encoded certificates.
    /// `key_der` is a DER-encoded private key as PKCS#1, PKCS#8, or SEC1. The
    /// `aws-lc-rs` and `ring` [`CryptoProvider`][crate::CryptoProvider]s support
    /// all three encodings, but other `CryptoProviders` may not.
    ///
    /// This function fails if `key_der` is invalid.
    pub fn with_client_auth_cert(
        self,
        cert_chain: Vec<CertificateDer<'static>>,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<ClientConfig, Error> {
        let certified_key = CertifiedKey::from_der(cert_chain, key_der, &self.provider)?;
        Ok(self.with_client_cert_resolver(Arc::new(SingleCertAndKey::from(certified_key))))
    }

    /// Do not support client auth.
    pub fn with_no_client_auth(self) -> ClientConfig {
        self.with_client_cert_resolver(Arc::new(handy::FailResolveClientCert {}))
    }

    /// Sets a [`ClientHelloFingerprinter`] to modify the ClientHello before sending.
    pub fn with_fingerprint(
        mut self,
        fingerprint: Arc<dyn crate::client::fingerprint::ClientHelloFingerprinter>,
    ) -> Self {
        // Automatically configure ECH GREASE if the fingerprinter requests it and no ECH mode is set.
        if self.state.client_ech_mode.is_none() && fingerprint.wants_ech_grease() {
            #[cfg(feature = "aws_lc_rs")]
            {
                use crate::crypto::hpke::Hpke;
                let hpke_suite = crate::crypto::aws_lc_rs::hpke::DH_KEM_X25519_HKDF_SHA256_AES_128;
                if let Ok((public_key, _)) = hpke_suite.generate_key_pair() {
                    self.state.client_ech_mode = Some(EchMode::Grease(
                        crate::client::EchGreaseConfig::new(hpke_suite, public_key),
                    ));
                }
            }
        }

        // Apply kx_group fixups from the fingerprint
        let (extra_groups, preferred_group) = fingerprint.kx_group_fixups();

        self.state.fingerprint = Some(fingerprint);
        let mut provider = (*self.provider).clone();

        for group in extra_groups {
            if !provider
                .kx_groups
                .iter()
                .any(|g| g.name() == group.name())
            {
                provider.kx_groups.push(group);
            }
        }

        if let Some(preferred) = preferred_group {
            if let Some(pos) = provider
                .kx_groups
                .iter()
                .position(|g| g.name() == preferred)
            {
                let group = provider.kx_groups.remove(pos);
                provider.kx_groups.insert(0, group);
            }
        }

        self.provider = Arc::new(provider);

        // Add available certificate compression/decompression support when fingerprinting.
        self.state.cert_compressors = Some(compress::default_cert_compressors().to_vec());
        self.state.cert_decompressors = Some(compress::default_cert_decompressors().to_vec());

        self
    }

    /// Sets a custom [`ResolvesClientCert`].
    pub fn with_client_cert_resolver(
        self,
        client_auth_cert_resolver: Arc<dyn ResolvesClientCert>,
    ) -> ClientConfig {
        #[cfg(feature = "tls12")]
        let require_ems = self.provider.fips();

        ClientConfig {
            provider: self.provider,
            alpn_protocols: Vec::new(),
            check_selected_alpn: true,
            resumption: Resumption::default(),
            max_fragment_size: None,
            client_auth_cert_resolver,
            versions: self.state.versions,
            enable_sni: true,
            verifier: self.state.verifier,
            key_log: Arc::new(NoKeyLog {}),
            enable_secret_extraction: false,
            enable_early_data: false,
            #[cfg(feature = "tls12")]
            require_ems,
            time_provider: self.time_provider,
            cert_compressors: self
                .state
                .cert_compressors
                .unwrap_or_default(),
            cert_compression_cache: Arc::new(compress::CompressionCache::default()),
            cert_decompressors: self
                .state
                .cert_decompressors
                .unwrap_or_default(),
            ech_mode: self.state.client_ech_mode,
            fingerprint: self.state.fingerprint,
        }
    }
}
