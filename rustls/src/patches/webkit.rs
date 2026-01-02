use crate::CertificateCompressionAlgorithm;
use crate::enums::{CipherSuite, SignatureScheme};
use crate::msgs::base::{Payload, PayloadU8};
use crate::msgs::codec::Codec;
use crate::msgs::enums::{ExtensionType, NamedGroup};
use crate::msgs::handshake::{ClientHelloPayload, KeyShareEntry, ProtocolName};
use crate::patches::UnknownExtension;
use crate::patches::grease::{GREASE_VALUES, get_grease_value};
use alloc::vec;
use alloc::vec::Vec;
use rand::seq::IndexedRandom;

pub(crate) fn apply_webkit_fingerprint(payload: &mut ClientHelloPayload, no_alpn: bool) {
    let mut rng = rand::rng();

    // Generate unique GREASE values for two extensions
    let grease_pool = GREASE_VALUES
        .choose_multiple(&mut rng, 2)
        .collect::<Vec<_>>();

    let grease_ext1 = *grease_pool[0];
    let grease_ext2 = *grease_pool[1];
    let grease_shared_group = get_grease_value(&mut rng); // Shared for groups, key_share
    let grease_cipher = get_grease_value(&mut rng);
    let grease_version = get_grease_value(&mut rng);

    // 1. Cipher Suites
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
        CipherSuite::TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
        CipherSuite::TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
        CipherSuite::TLS_RSA_WITH_3DES_EDE_CBC_SHA,
    ];

    // 2. Очистка и подготовка расширений
    payload
        .extensions
        .contiguous_extensions
        .clear();
    payload
        .extensions
        .custom_extensions
        .clear();
    payload.extensions.session_ticket = None;

    // 2.1 GREASE Extension (1)
    add_custom_ext(payload, grease_ext1, vec![]);

    // 2.2 server_name (SNI)
    payload
        .extensions
        .contiguous_extensions
        .push(ExtensionType::ServerName);

    // 2.3 extended_master_secret
    payload
        .extensions
        .extended_master_secret_request = Some(());
    payload
        .extensions
        .contiguous_extensions
        .push(ExtensionType::ExtendedMasterSecret);

    // 2.4 renegotiation_info
    payload.extensions.renegotiation_info = Some(PayloadU8::new(vec![]));
    payload
        .extensions
        .contiguous_extensions
        .push(ExtensionType::RenegotiationInfo);

    // 2.5 supported_groups
    payload.extensions.named_groups = Some(vec![
        NamedGroup::Unknown(grease_shared_group),
        NamedGroup::X25519,
        NamedGroup::secp256r1,
        NamedGroup::secp384r1,
        NamedGroup::secp521r1,
    ]);
    payload
        .extensions
        .contiguous_extensions
        .push(ExtensionType::EllipticCurves);

    // 2.6 ec_point_formats
    payload
        .extensions
        .contiguous_extensions
        .push(ExtensionType::ECPointFormats);

    // 2.7 application_layer_protocol_negotiation
    if !no_alpn {
        if payload.extensions.protocols.is_none() {
            payload.extensions.protocols = Some(vec![
                ProtocolName::from(b"h2".to_vec()),
                ProtocolName::from(b"http/1.1".to_vec()),
            ]);
        }
        payload
            .extensions
            .contiguous_extensions
            .push(ExtensionType::ALProtocolNegotiation);
    }

    // 2.8 status_request (OCSP)
    payload
        .extensions
        .contiguous_extensions
        .push(ExtensionType::StatusRequest);

    // 2.9 signature_algorithms
    payload.extensions.signature_schemes = Some(vec![
        SignatureScheme::ECDSA_NISTP256_SHA256, // 0403
        SignatureScheme::RSA_PSS_SHA256,        // 0804
        SignatureScheme::RSA_PKCS1_SHA256,      // 0401
        SignatureScheme::ECDSA_NISTP384_SHA384, // 0503
        SignatureScheme::RSA_PSS_SHA384,        // 0805
        SignatureScheme::RSA_PSS_SHA384,        // 0805 (duplicate in Safari fingerprint)
        SignatureScheme::RSA_PKCS1_SHA384,      // 0501
        SignatureScheme::RSA_PSS_SHA512,        // 0806
        SignatureScheme::RSA_PKCS1_SHA512,      // 0601
        SignatureScheme::RSA_PKCS1_SHA1,        // 0201
    ]);
    payload
        .extensions
        .contiguous_extensions
        .push(ExtensionType::SignatureAlgorithms);

    // 2.10 signed_certificate_timestamps (SCT)
    add_custom_ext(payload, 0x0012, vec![]);

    // 2.11 key_share
    if let Some(shares) = &mut payload.extensions.key_shares {
        let grease_entry = KeyShareEntry::new(NamedGroup::Unknown(grease_shared_group), vec![0x00]);

        // Оставляем только X25519
        shares.retain(|share| share.group == NamedGroup::X25519);

        // Вставляем GREASE в начало
        shares.insert(0, grease_entry);

        payload
            .extensions
            .contiguous_extensions
            .push(ExtensionType::KeyShare);
    }

    // 2.12 psk_key_exchange_modes
    payload
        .extensions
        .contiguous_extensions
        .push(ExtensionType::PSKKeyExchangeModes);

    // 2.13 supported_versions
    let mut ver_payload = vec![0x0a]; // length 10 (5 versions * 2 bytes)
    ver_payload.extend_from_slice(&grease_version.to_be_bytes());
    ver_payload.extend_from_slice(&0x0304u16.to_be_bytes()); // TLS 1.3
    ver_payload.extend_from_slice(&0x0303u16.to_be_bytes()); // TLS 1.2
    ver_payload.extend_from_slice(&0x0302u16.to_be_bytes()); // TLS 1.1
    ver_payload.extend_from_slice(&0x0301u16.to_be_bytes()); // TLS 1.0

    // Удаляем стандартный supported_versions и заменяем кастомным
    payload.extensions.supported_versions = None;
    add_custom_ext(payload, 0x002b, ver_payload);

    // 2.14 compress_certificate (zlib)
    payload
        .extensions
        .certificate_compression_algorithms = Some(vec![CertificateCompressionAlgorithm::Zlib]);
    payload
        .extensions
        .contiguous_extensions
        .push(ExtensionType::CompressCertificate);

    // 2.15 GREASE Extension (2)
    add_custom_ext(payload, grease_ext2, vec![0x00]);

    // 2.16 padding
    let mut temp = Vec::new();
    payload.encode(&mut temp);

    let current_total_len = temp.len();
    let target_len = 512;

    if current_total_len < target_len {
        let pad_len = target_len - current_total_len - 8;
        if pad_len > 0 {
            add_custom_ext(payload, 0x0015, vec![0u8; pad_len]);
        }
    }
}

fn add_custom_ext(payload: &mut ClientHelloPayload, typ: u16, data: Vec<u8>) {
    let etype = ExtensionType::from(typ);
    payload
        .extensions
        .custom_extensions
        .push(UnknownExtension {
            typ: etype,
            payload: Payload::new(data),
        });
    payload
        .extensions
        .contiguous_extensions
        .push(etype);
}
