use alloc::vec;
use alloc::vec::Vec;

use super::{ClientHelloFingerprinter, GreaseRng, get_grease_value};
use crate::enums::{CertificateCompressionAlgorithm, CipherSuite, SignatureScheme};
use crate::msgs::base::{Payload, PayloadU16};
use crate::msgs::enums::{ExtensionType, NamedGroup};
use crate::msgs::handshake::{
    CertificateStatusRequest, ClientHelloPayload, ClientSessionTicket, EncryptedClientHello,
    KeyShareEntry, ProtocolName, PskKeyExchangeModes, SupportedEcPointFormats, UnknownExtension,
};

/// Emulates the TLS fingerprint of Google Chrome (desktop).
///
/// This matches the Wireshark capture from Chrome on macOS Sequoia.
/// Chrome permutes (shuffles) its extensions between the initial GREASE
/// and trailing GREASE extensions on every Client Hello payload.
#[derive(Clone, Debug, Default)]
pub struct ChromeFingerprint;

#[allow(private_interfaces)]
impl ClientHelloFingerprinter for ChromeFingerprint {
    fn wants_ech_grease(&self) -> bool {
        true
    }

    fn kx_group_fixups(
        &self,
    ) -> (
        Vec<&'static dyn crate::crypto::SupportedKxGroup>,
        Option<NamedGroup>,
    ) {
        (Vec::new(), Some(NamedGroup::X25519MLKEM768))
    }

    fn apply(&self, payload: &mut ClientHelloPayload, is_retry: bool) {
        // Seed RNG from session ID / random so GREASE values and extension order
        // vary across connections but remain stable across CH1/CH2 retries.
        let seed_bytes = if !payload.session_id.is_empty() {
            payload.session_id.as_ref()
        } else {
            &payload.random.0
        };
        let mut rng = GreaseRng::from_session_id(seed_bytes);

        let grease_cipher = get_grease_value(&mut rng);
        let grease_group = get_grease_value(&mut rng);
        let grease_version = get_grease_value(&mut rng);
        let grease_ext1 = get_grease_value(&mut rng);
        // Ensure the two GREASE extension values are different.
        let mut grease_ext2 = get_grease_value(&mut rng);
        while grease_ext2 == grease_ext1 {
            grease_ext2 = get_grease_value(&mut rng);
        }

        // 1. Cipher suites — exact Chrome order, 16 suites.
        payload.cipher_suites = vec![
            CipherSuite::Unknown(grease_cipher),
            CipherSuite::TLS13_AES_128_GCM_SHA256,
            CipherSuite::TLS13_AES_256_GCM_SHA384,
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA,
        ];

        // 2. Prepare extension payloads.
        {
            let exts = &mut payload.extensions;
            exts.contiguous_extensions.clear();
            exts.unknown_extensions.clear();
            exts.order_seed = 0;

            // 2.1 GREASE extension 1 (len=0)
            exts.unknown_extensions
                .push(UnknownExtension {
                    typ: ExtensionType::Unknown(grease_ext1),
                    payload: Payload::new(Vec::new()),
                });

            // 2.2 supported_groups
            exts.named_groups = Some(vec![
                NamedGroup::Unknown(grease_group),
                NamedGroup::X25519MLKEM768,
                NamedGroup::X25519,
                NamedGroup::secp256r1,
                NamedGroup::secp384r1,
            ]);

            // 2.3 supported_versions
            exts.supported_versions = None;
            let mut ver_payload = vec![0x06]; // length 6 (3 versions × 2)
            ver_payload.extend_from_slice(&grease_version.to_be_bytes());
            ver_payload.extend_from_slice(&[0x03, 0x04]); // TLS 1.3
            ver_payload.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
            exts.unknown_extensions
                .push(UnknownExtension {
                    typ: ExtensionType::SupportedVersions,
                    payload: Payload::new(ver_payload),
                });

            // 2.4 psk_key_exchange_modes
            exts.preshared_key_modes = Some(PskKeyExchangeModes {
                psk_dhe: true,
                psk: false,
            });

            // 2.5 extended_master_secret
            exts.extended_master_secret_request = Some(());

            // 2.7 signed_certificate_timestamp (len=0)
            exts.unknown_extensions
                .push(UnknownExtension {
                    typ: ExtensionType::Unknown(0x0012),
                    payload: Payload::new(Vec::new()),
                });

            // 2.8 application_settings (ALPS: h2)
            exts.unknown_extensions
                .push(UnknownExtension {
                    typ: ExtensionType::Unknown(0x44cd),
                    payload: Payload::new(vec![0x00, 0x03, 0x02, b'h', b'2']),
                });

            // 2.9 ALPN — Chrome sends h2, http/1.1
            if exts.protocols.is_none() {
                exts.protocols = Some(vec![
                    ProtocolName::from(b"h2".to_vec()),
                    ProtocolName::from(b"http/1.1".to_vec()),
                ]);
            }

            // 2.10 ec_point_formats
            exts.ec_point_formats = Some(SupportedEcPointFormats::default());

            // 2.11 renegotiation_info
            exts.renegotiation_info = Some(crate::msgs::base::PayloadU8::empty());

            // 2.12 key_share
            if let Some(shares) = &mut exts.key_shares {
                if !is_retry {
                    shares.retain(|s| {
                        s.group == NamedGroup::X25519MLKEM768 || s.group == NamedGroup::X25519
                    });
                    let grease_entry =
                        KeyShareEntry::new(NamedGroup::Unknown(grease_group), vec![0x00]);
                    shares.insert(0, grease_entry);
                }
            }

            // 2.13 session_ticket
            if exts.session_ticket.is_none() {
                exts.session_ticket = Some(ClientSessionTicket::Request);
            }

            // 2.13.1 Vary GREASE ECH payload length randomly across 32-byte blocks (144..272 bytes),
            // matching Chrome's dynamic padding behavior.
            if let Some(EncryptedClientHello::Outer(ref mut outer)) = exts.encrypted_client_hello {
                let block_count = 4 + (rng.next_usize(5)); // 4 to 8 blocks of 32 bytes (144..272 bytes)
                let payload_len = block_count * 32 + 16;
                let mut dummy_payload = vec![0u8; payload_len];
                for (i, b) in dummy_payload.iter_mut().enumerate() {
                    *b = (rng.next_usize(256) ^ i) as u8;
                }
                outer.payload = PayloadU16::new(dummy_payload);
            }

            // 2.14 signature_algorithms
            exts.signature_schemes = Some(vec![
                SignatureScheme::Unknown(0x0904), // mldsa44
                SignatureScheme::Unknown(0x0905), // mldsa65
                SignatureScheme::Unknown(0x0906), // mldsa87
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::RSA_PKCS1_SHA512,
            ]);

            // 2.15 status_request (OCSP)
            exts.certificate_status_request = Some(CertificateStatusRequest::build_ocsp());

            // 2.16 compress_certificate (Brotli)
            exts.certificate_compression_algorithms =
                Some(vec![CertificateCompressionAlgorithm::Brotli]);

            // 2.17 Second GREASE extension (len=1, data=0x00)
            exts.unknown_extensions
                .push(UnknownExtension {
                    typ: ExtensionType::Unknown(grease_ext2),
                    payload: Payload::new(vec![0x00]),
                });

            // 3. Assemble and permute (shuffle) middle extensions between GREASE 1 and GREASE 2
            let mut inner_exts = vec![
                ExtensionType::EllipticCurves,
                ExtensionType::SupportedVersions,
                ExtensionType::PSKKeyExchangeModes,
                ExtensionType::ExtendedMasterSecret,
                ExtensionType::Unknown(0x0012), // SCT
                ExtensionType::Unknown(0x44cd), // ALPS
                ExtensionType::ALProtocolNegotiation,
                ExtensionType::ECPointFormats,
                ExtensionType::RenegotiationInfo,
                ExtensionType::SessionTicket,
                ExtensionType::SignatureAlgorithms,
                ExtensionType::StatusRequest,
                ExtensionType::CompressCertificate,
            ];

            if exts.server_name.is_some() {
                inner_exts.push(ExtensionType::ServerName);
            }
            if exts.key_shares.is_some() {
                inner_exts.push(ExtensionType::KeyShare);
            }
            if exts.encrypted_client_hello.is_some() {
                inner_exts.push(ExtensionType::EncryptedClientHello);
            }

            // Fisher-Yates shuffle using PRNG
            for i in (1..inner_exts.len()).rev() {
                let j = rng.next_usize(i + 1);
                inner_exts.swap(i, j);
            }

            exts.contiguous_extensions
                .push(ExtensionType::Unknown(grease_ext1));
            exts.contiguous_extensions
                .extend(inner_exts);
            exts.contiguous_extensions
                .push(ExtensionType::Unknown(grease_ext2));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProtocolVersion;
    use crate::msgs::handshake::{Random, ServerNamePayload, SessionId};
    use crate::pki_types::DnsName;
    use alloc::boxed::Box;

    #[test]
    fn test_chrome_fingerprint_apply() {
        let dns_name = DnsName::try_from("example.com").unwrap();
        let mut payload = ClientHelloPayload {
            client_version: ProtocolVersion::TLSv1_2,
            random: Random::from([0u8; 32]),
            session_id: SessionId::empty(),
            cipher_suites: vec![],
            compression_methods: vec![],
            extensions: Box::default(),
        };

        payload.extensions.server_name = Some(ServerNamePayload::SingleDnsName(dns_name));
        payload.extensions.key_shares =
            Some(vec![KeyShareEntry::new(NamedGroup::X25519, vec![0; 32])]);

        let fp = ChromeFingerprint;
        fp.apply(&mut payload, false);

        // Verify cipher suites count
        assert_eq!(payload.cipher_suites.len(), 16);
        assert!(matches!(payload.cipher_suites[0], CipherSuite::Unknown(_)));
        assert_eq!(
            payload.cipher_suites[1],
            CipherSuite::TLS13_AES_128_GCM_SHA256
        );

        // Verify supported groups
        let groups = payload
            .extensions
            .named_groups
            .as_ref()
            .unwrap();
        assert_eq!(groups.len(), 5);
        assert!(matches!(groups[0], NamedGroup::Unknown(_)));
        assert_eq!(groups[1], NamedGroup::X25519MLKEM768);
        assert_eq!(groups[2], NamedGroup::X25519);

        // Verify certificate compression
        let cert_comp = payload
            .extensions
            .certificate_compression_algorithms
            .as_ref()
            .unwrap();
        assert_eq!(cert_comp, &[CertificateCompressionAlgorithm::Brotli]);

        // Verify signature algorithms
        let sig_schemes = payload
            .extensions
            .signature_schemes
            .as_ref()
            .unwrap();
        assert_eq!(sig_schemes.len(), 11);
        assert_eq!(sig_schemes[0], SignatureScheme::Unknown(0x0904)); // mldsa44

        // Verify total contiguous extensions count (1 GREASE + inner extensions + 1 GREASE)
        let ext_types = &payload.extensions.contiguous_extensions;
        assert!(ext_types.len() >= 17);
        assert!(matches!(ext_types[0], ExtensionType::Unknown(_)));
        assert!(matches!(
            ext_types[ext_types.len() - 1],
            ExtensionType::Unknown(_)
        ));
    }
}
