use crate::enums::{CipherSuite, SignatureScheme};
use crate::msgs::base::{Payload, PayloadU8, PayloadU16};
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::{ExtensionType, NamedGroup};
use crate::msgs::handshake::{
    CertificateStatusRequest, ClientHelloPayload, KeyShareEntry, OcspCertificateStatusRequest,
};
use crate::{CertificateCompressionAlgorithm, error::InvalidMessage};
use alloc::vec;
use alloc::vec::Vec;
use rand::Rng;
use rand::seq::IndexedRandom;

// GREASE значения согласно RFC 8701
const GREASE_VALUES: [u16; 16] = [
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
];

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct UnknownExtension {
    pub(crate) typ: ExtensionType,
    pub(crate) payload: Payload<'static>,
}

impl Codec<'_> for UnknownExtension {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.typ.encode(bytes);
        let payload_bytes = self.payload.bytes();
        ((payload_bytes.len()) as u16).encode(bytes);
        bytes.extend_from_slice(payload_bytes);
    }

    fn read(_r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        Err(InvalidMessage::MissingData("UnknownExtension"))
    }
}

fn get_grease_value<R: Rng>(rng: &mut R) -> u16 {
    let index = rng.random_range(0..GREASE_VALUES.len());
    GREASE_VALUES[index]
}

pub(crate) fn apply_webkit_fingerprint(payload: &mut ClientHelloPayload) {
    let mut rng = rand::rng();

    // Generate two unique grease values for extension types
    let grease_values = GREASE_VALUES
        .choose_multiple(&mut rng, 2)
        .collect::<Vec<_>>();

    let grease_ext1 = *grease_values[0];
    let grease_ext2 = *grease_values[1];

    // 1. Cipher Suites
    payload.cipher_suites = vec![
        CipherSuite::Unknown(get_grease_value(&mut rng)),
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
        NamedGroup::Unknown(get_grease_value(&mut rng)),
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
    if payload.extensions.protocols.is_some() {
        payload
            .extensions
            .contiguous_extensions
            .push(ExtensionType::ALProtocolNegotiation);
    }

    // 2.8 status_request (OCSP)
    payload
        .extensions
        .certificate_status_request = Some(CertificateStatusRequest::Ocsp(
        OcspCertificateStatusRequest {
            responder_ids: vec![],
            extensions: PayloadU16::empty(),
        },
    ));
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
        let grease_group = get_grease_value(&mut rng);
        let grease_entry = KeyShareEntry::new(NamedGroup::Unknown(grease_group), vec![0x00]);

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
    let g_ver = get_grease_value(&mut rng);
    let mut ver_payload = vec![0x0a]; // length 10 (5 versions * 2 bytes)
    ver_payload.extend_from_slice(&g_ver.to_be_bytes());
    ver_payload.extend_from_slice(&0x0304u16.to_be_bytes());
    ver_payload.extend_from_slice(&0x0303u16.to_be_bytes());
    ver_payload.extend_from_slice(&0x0302u16.to_be_bytes());
    ver_payload.extend_from_slice(&0x0301u16.to_be_bytes());

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
