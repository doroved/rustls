use alloc::vec;
use alloc::vec::Vec;

use super::{ClientHelloFingerprinter, GreaseRng, get_grease_value};
use crate::enums::{CertificateCompressionAlgorithm, CipherSuite, SignatureScheme};
use crate::msgs::base::Payload;
use crate::msgs::enums::{ExtensionType, NamedGroup};
use crate::msgs::handshake::{
    CertificateStatusRequest, ClientHelloPayload, KeyShareEntry, ProtocolName,
    PskKeyExchangeModes, SupportedEcPointFormats, UnknownExtension,
};
use crate::msgs::codec::Codec;

/// Emulates the TLS fingerprint of Safari on macOS / WebKit on iOS.
///
/// This matches the Wireshark capture from Safari 26.0.1 on macOS Sequoia 15.7.1.
#[derive(Clone, Debug, Default)]
pub struct SafariFingerprint;

#[allow(private_interfaces)]
impl ClientHelloFingerprinter for SafariFingerprint {
    fn apply(&self, payload: &mut ClientHelloPayload, is_retry: bool) {
        // Seed RNG from session ID so GREASE values are stable across CH1/CH2.
        let mut rng = GreaseRng::from_session_id(payload.session_id.as_ref());

        let grease_cipher = get_grease_value(&mut rng);
        let grease_group = get_grease_value(&mut rng);
        let grease_version = get_grease_value(&mut rng);
        let grease_ext1 = get_grease_value(&mut rng);
        // Ensure the two GREASE extension values are different,
        // otherwise collect_used() emits the type twice but encode_one()
        // only encodes the first matching unknown extension.
        let mut grease_ext2 = get_grease_value(&mut rng);
        while grease_ext2 == grease_ext1 {
            grease_ext2 = get_grease_value(&mut rng);
        }

        // 1. Cipher suites — exact Safari order, 21 suites.
        payload.cipher_suites = vec![
            CipherSuite::Unknown(grease_cipher),
            CipherSuite::TLS13_AES_128_GCM_SHA256,
            CipherSuite::TLS13_AES_256_GCM_SHA384,
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite::Unknown(0xc008), // TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
            CipherSuite::Unknown(0xc012), // TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
            CipherSuite::Unknown(0x000a), // TLS_RSA_WITH_3DES_EDE_CBC_SHA
        ];

        // 2. Prepare extensions.
        {
            let exts = &mut payload.extensions;
            exts.contiguous_extensions.clear();
            exts.unknown_extensions.clear();
            exts.session_ticket = None;
            exts.order_seed = 0;

            // 2.1 GREASE extension (empty)
            exts.unknown_extensions
                .push(UnknownExtension {
                    typ: ExtensionType::Unknown(grease_ext1),
                    payload: Payload::new(Vec::new()),
                });
            exts.contiguous_extensions
                .push(ExtensionType::Unknown(grease_ext1));

            // 2.2 server_name (SNI)
            if exts.server_name.is_some() {
                exts.contiguous_extensions
                    .push(ExtensionType::ServerName);
            }

            // 2.3 extended_master_secret
            exts.extended_master_secret_request = Some(());
            exts.contiguous_extensions
                .push(ExtensionType::ExtendedMasterSecret);

            // 2.4 renegotiation_info (replaces SCSV)
            exts.renegotiation_info = Some(crate::msgs::base::PayloadU8::empty());
            exts.contiguous_extensions
                .push(ExtensionType::RenegotiationInfo);

            // 2.5 supported_groups
            exts.named_groups = Some(vec![
                NamedGroup::Unknown(grease_group),
                NamedGroup::X25519,
                NamedGroup::secp256r1,
                NamedGroup::secp384r1,
                NamedGroup::secp521r1,
            ]);
            exts.contiguous_extensions
                .push(ExtensionType::EllipticCurves);

            // 2.6 ec_point_formats
            exts.ec_point_formats = Some(SupportedEcPointFormats::default());
            exts.contiguous_extensions
                .push(ExtensionType::ECPointFormats);

            // 2.7 ALPN — Safari always sends h2, http/1.1
            // Only set if user hasn't explicitly configured ALPN.
            if exts.protocols.is_none() {
                exts.protocols = Some(vec![
                    ProtocolName::from(b"h2".to_vec()),
                    ProtocolName::from(b"http/1.1".to_vec()),
                ]);
            }
            exts.contiguous_extensions
                .push(ExtensionType::ALProtocolNegotiation);

            // 2.8 status_request (OCSP)
            exts.certificate_status_request = Some(CertificateStatusRequest::build_ocsp());
            exts.contiguous_extensions
                .push(ExtensionType::StatusRequest);

            // 2.9 signature_algorithms (with duplicate RSA_PSS_SHA384)
            exts.signature_schemes = Some(vec![
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::Unknown(0x0805), // duplicate RSA_PSS_SHA384
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::RSA_PKCS1_SHA1,
            ]);
            exts.contiguous_extensions
                .push(ExtensionType::SignatureAlgorithms);

            // 2.10 signed_certificate_timestamp (empty)
            exts.unknown_extensions
                .push(UnknownExtension {
                    typ: ExtensionType::Unknown(0x0012),
                    payload: Payload::new(Vec::new()),
                });
            exts.contiguous_extensions
                .push(ExtensionType::Unknown(0x0012));

            // 2.11 key_share
            if let Some(shares) = &mut exts.key_shares {
                if !is_retry {
                    // CH1: keep only x25519, prepend GREASE
                    shares.retain(|s| s.group == NamedGroup::X25519);
                    let grease_entry = KeyShareEntry::new(NamedGroup::Unknown(grease_group), vec![0x00]);
                    shares.insert(0, grease_entry);
                }
                // CH2: rustls already has the requested group only — leave it.
                exts.contiguous_extensions
                    .push(ExtensionType::KeyShare);
            }

            // 2.12 psk_key_exchange_modes
            exts.preshared_key_modes = Some(PskKeyExchangeModes {
                psk_dhe: true,
                psk: false,
            });
            exts.contiguous_extensions
                .push(ExtensionType::PSKKeyExchangeModes);

            // 2.13 supported_versions — custom encoding with TLS 1.1/1.0
            // Remove standard field and inject raw bytes as unknown extension.
            exts.supported_versions = None;
            let mut ver_payload = vec![0x0a]; // length 10 (5 versions × 2)
            ver_payload.extend_from_slice(&grease_version.to_be_bytes());
            ver_payload.extend_from_slice(&[0x03, 0x04]); // TLS 1.3
            ver_payload.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
            ver_payload.extend_from_slice(&[0x03, 0x02]); // TLS 1.1
            ver_payload.extend_from_slice(&[0x03, 0x01]); // TLS 1.0
            exts.unknown_extensions
                .push(UnknownExtension {
                    typ: ExtensionType::SupportedVersions,
                    payload: Payload::new(ver_payload),
                });
            exts.contiguous_extensions
                .push(ExtensionType::SupportedVersions);

            // 2.14 compress_certificate (zlib)
            exts.certificate_compression_algorithms =
                Some(vec![CertificateCompressionAlgorithm::Zlib]);
            exts.contiguous_extensions
                .push(ExtensionType::CompressCertificate);

            // 2.15 Second GREASE extension (len=1, data=0x00)
            exts.unknown_extensions
                .push(UnknownExtension {
                    typ: ExtensionType::Unknown(grease_ext2),
                    payload: Payload::new(vec![0x00]),
                });
            exts.contiguous_extensions
                .push(ExtensionType::Unknown(grease_ext2));
        } // end of exts borrow

        // 2.16 padding — only in initial ClientHello
        if !is_retry {
            let mut temp = Vec::new();
            payload.encode(&mut temp);
            let current_body_len = temp.len();
            // Target: TLS record payload = 512 bytes.
            // Handshake header = 4 bytes, so body target = 508.
            // Padding extension header = 4 bytes.
            // pad_data = 508 - current_body_len - 4
            //          = 504 - current_body_len
            // Old patch used: 512 - current_body_len - 8  => same result.
            let pad_data_len = 512i32 - current_body_len as i32 - 8;
            if pad_data_len > 0 {
                payload
                    .extensions
                    .unknown_extensions
                    .push(UnknownExtension {
                        typ: ExtensionType::Unknown(0x0015), // padding
                        payload: Payload::new(vec![0u8; pad_data_len as usize]),
                    });
                payload
                    .extensions
                    .contiguous_extensions
                    .push(ExtensionType::Unknown(0x0015));
            }
        }
    }
}
