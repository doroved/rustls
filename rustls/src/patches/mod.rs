// All patches in rustls, marked as #PATH

use pki_types::DnsName;

/// Disable SNI normalization for the given DNS name.
pub(crate) fn disable_sni_normalization(value: &DnsName<'_>) -> DnsName<'static> {
    value.to_owned()
}

/// Generate webkit handshake
pub(crate) fn webkit_handshake() {
    todo!("Implement webkit_handshake")
}
