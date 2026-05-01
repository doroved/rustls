use crate::msgs::handshake::ClientHelloPayload;

/// A trait for modifying [`ClientHelloPayload`] to emulate a specific browser fingerprint.
///
/// Implementations can reorder extensions, replace cipher suites, inject GREASE values,
/// and add padding to match a target TLS fingerprint.
///
/// The [`apply`] method is called after rustls has built the default `ClientHelloPayload`,
/// but before it is encoded and sent on the wire.
#[allow(private_interfaces)]
pub trait ClientHelloFingerprinter: Send + Sync + 'static + core::fmt::Debug {
    /// Modify the given `ClientHelloPayload` in-place.
    ///
    /// * `payload` — the default rustls ClientHello, ready to be modified.
    /// * `is_retry` — `true` if this is a ClientHello sent in response to a HelloRetryRequest.
    fn apply(&self, payload: &mut ClientHelloPayload, is_retry: bool);
}

/// Browser fingerprint implementations.
pub mod safari;

mod grease;
pub(crate) use grease::{get_grease_value, GreaseRng};
