// #START_PATCH
use super::kx::{KxGroup, uncompressed_point};
use super::ring_like::agreement;
use crate::crypto::SupportedKxGroup;
use crate::msgs::enums::NamedGroup;

/// Ephemeral ECDH on secp521r1 (aka NIST-P521)
pub static SECP521R1: &dyn SupportedKxGroup = &KxGroup {
    name: NamedGroup::secp521r1,
    agreement_algorithm: &agreement::ECDH_P521,
    fips_allowed: true,
    pub_key_validator: uncompressed_point,
};
// #END_PATCH
