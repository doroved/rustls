use alloc::vec::Vec;

use crate::crypto::SupportedKxGroup;
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

    /// Returns `true` if this browser fingerprint sends ECH GREASE by default.
    fn wants_ech_grease(&self) -> bool {
        false
    }

    /// Returns additional `kx_groups` that this fingerprint requires in the provider,
    /// and optionally a group name that should be moved to position 0.
    ///
    /// The first element of the tuple is a list of extra groups to append.
    /// The second element is the `NamedGroup` that should be first (for `initial_key_share`).
    fn kx_group_fixups(
        &self,
    ) -> (
        Vec<&'static dyn SupportedKxGroup>,
        Option<crate::msgs::enums::NamedGroup>,
    ) {
        (Vec::new(), None)
    }
}

/// Browser fingerprint implementations.
/// Google Chrome TLS fingerprint emulation.
pub mod chrome;
/// WebKit (Safari / iOS) TLS fingerprint emulation.
pub mod webkit;

mod grease;
pub(crate) use grease::{GreaseRng, get_grease_value};
