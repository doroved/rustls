use crate::CertificateCompressionAlgorithm;
use crate::enums::{CipherSuite, SignatureScheme};
use crate::msgs::base::{Payload, PayloadU8};
use crate::msgs::enums::{ExtensionType, NamedGroup};
use crate::msgs::handshake::{ClientHelloPayload, KeyShareEntry, ProtocolName};
use crate::patches::UnknownExtension;
use crate::patches::grease::{GREASE_VALUES, get_grease_value};
use alloc::vec;
use alloc::vec::Vec;
use rand::Rng;
use rand::seq::{IndexedRandom, SliceRandom};

pub(crate) fn apply_chrome_fingerprint(payload: &mut ClientHelloPayload, no_alpn: bool) {
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

    // Clear and prepare extensions
    payload
        .extensions
        .contiguous_extensions
        .clear();
    payload
        .extensions
        .custom_extensions
        .clear();

    // We will collect extension types here to shuffle them later
    let mut middle_extensions = Vec::new();

    // --- Prepare Standard Extensions ---

    // status_request (OCSP)
    middle_extensions.push(ExtensionType::StatusRequest);

    // extended_master_secret
    middle_extensions.push(ExtensionType::ExtendedMasterSecret);

    // application_layer_protocol_negotiation
    if !no_alpn {
        if payload.extensions.protocols.is_none() {
            payload.extensions.protocols = Some(vec![
                ProtocolName::from(b"h2".to_vec()),
                ProtocolName::from(b"http/1.1".to_vec()),
            ]);
        }
        middle_extensions.push(ExtensionType::ALProtocolNegotiation);
    }

    // ec_point_formats
    middle_extensions.push(ExtensionType::ECPointFormats);

    // psk_key_exchange_modes
    middle_extensions.push(ExtensionType::PSKKeyExchangeModes);

    // compress_certificate (brotli)
    payload
        .extensions
        .certificate_compression_algorithms = Some(vec![CertificateCompressionAlgorithm::Brotli]);
    middle_extensions.push(ExtensionType::CompressCertificate);

    // renegotiation_info
    payload.extensions.renegotiation_info = Some(PayloadU8::new(vec![]));
    middle_extensions.push(ExtensionType::RenegotiationInfo);

    // signature_algorithms
    payload.extensions.signature_schemes = Some(vec![
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::RSA_PSS_SHA256,
        SignatureScheme::RSA_PKCS1_SHA256,
        SignatureScheme::ECDSA_NISTP384_SHA384,
        SignatureScheme::RSA_PSS_SHA384,
        SignatureScheme::RSA_PKCS1_SHA384,
        SignatureScheme::RSA_PSS_SHA512,
        SignatureScheme::RSA_PKCS1_SHA512,
    ]);
    middle_extensions.push(ExtensionType::SignatureAlgorithms);

    // server_name
    middle_extensions.push(ExtensionType::ServerName);

    // session_ticket
    middle_extensions.push(ExtensionType::SessionTicket);

    // key_share
    if let Some(shares) = &mut payload.extensions.key_shares {
        let grease_entry = KeyShareEntry::new(NamedGroup::Unknown(grease_shared_group), vec![0x00]);
        let mut new_shares = Vec::new();
        new_shares.push(grease_entry);
        if let Some(pos) = shares
            .iter()
            .position(|s| s.group == NamedGroup::X25519MLKEM768)
        {
            new_shares.push(shares.remove(pos));
        }
        if let Some(pos) = shares
            .iter()
            .position(|s| s.group == NamedGroup::X25519)
        {
            new_shares.push(shares.remove(pos));
        }
        new_shares.append(shares);
        *shares = new_shares;
        middle_extensions.push(ExtensionType::KeyShare);
    }

    // supported_groups
    payload.extensions.named_groups = Some(vec![
        NamedGroup::Unknown(grease_shared_group),
        NamedGroup::X25519MLKEM768,
        NamedGroup::X25519,
        NamedGroup::secp256r1,
        NamedGroup::secp384r1,
    ]);
    middle_extensions.push(ExtensionType::EllipticCurves);

    // --- Prepare Custom Extensions ---

    // supported_versions (custom with GREASE)
    // Replace standard supported_versions
    payload.extensions.supported_versions = None;
    let mut ver_payload = vec![0x06]; // Length of versions list (3 * 2 bytes)
    ver_payload.extend_from_slice(&grease_version.to_be_bytes());
    ver_payload.extend_from_slice(&0x0304u16.to_be_bytes()); // TLS 1.3
    ver_payload.extend_from_slice(&0x0303u16.to_be_bytes()); // TLS 1.2
    add_custom_data(payload, 0x002b, ver_payload);
    middle_extensions.push(ExtensionType::SupportedVersions);

    // signed_certificate_timestamp (SCT)
    add_custom_data(payload, 0x0012, vec![]);
    middle_extensions.push(ExtensionType::SCT);

    // application_settings (ALPS) - 17613
    let alps_payload = vec![0x00, 0x03, 0x02, 0x68, 0x32]; // h2
    add_custom_data(payload, 17613, alps_payload);
    middle_extensions.push(ExtensionType::from(17613));

    // encrypted_client_hello
    if payload
        .extensions
        .encrypted_client_hello
        .is_some()
    {
        middle_extensions.push(ExtensionType::EncryptedClientHello);
    } else {
        // Simulate ECH
        let mut ech_payload = Vec::new();
        ech_payload.push(0x00); // ClientHello type: Outer
        ech_payload.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // KDF + AEAD
        ech_payload.push(rng.random()); // Config Id
        ech_payload.extend_from_slice(&32u16.to_be_bytes()); // Enc length
        let enc: Vec<u8> = (0..32).map(|_| rng.random()).collect();
        ech_payload.extend_from_slice(&enc);
        ech_payload.extend_from_slice(&240u16.to_be_bytes()); // Payload length
        let inner: Vec<u8> = (0..240).map(|_| rng.random()).collect();
        ech_payload.extend_from_slice(&inner);

        add_custom_data(payload, 0xfe0d, ech_payload);
        middle_extensions.push(ExtensionType::EncryptedClientHello);
    }

    // --- Build final order ---

    // 1. GREASE 1
    add_custom_data(payload, grease_ext1, vec![]);
    payload
        .extensions
        .contiguous_extensions
        .push(ExtensionType::from(grease_ext1));

    // 2. Shuffle Middle Extensions
    middle_extensions.shuffle(&mut rng);
    payload
        .extensions
        .contiguous_extensions
        .extend(middle_extensions);

    // 3. GREASE Last
    add_custom_data(payload, grease_ext2, vec![0x00]);
    payload
        .extensions
        .contiguous_extensions
        .push(ExtensionType::from(grease_ext2));
}

// Helper to add data to custom_extensions ONLY (not contiguous_extensions yet)
fn add_custom_data(payload: &mut ClientHelloPayload, typ: u16, data: Vec<u8>) {
    let etype = ExtensionType::from(typ);
    payload
        .extensions
        .custom_extensions
        .push(UnknownExtension {
            typ: etype,
            payload: Payload::new(data),
        });
}
