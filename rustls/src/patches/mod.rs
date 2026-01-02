// All patches in rustls, marked as #PATCH or #START_PATCH/#END_PATCH
pub(crate) mod chrome;
pub(crate) mod grease;
pub(crate) mod webkit;

use crate::error::InvalidMessage;
use crate::msgs::base::Payload;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::ExtensionType;
use alloc::vec::Vec;

/// Which TLS fingerprint to use
#[derive(Clone, Debug, PartialEq)]
pub enum TlsFingerprint {
    /// Chrome-like fingerprint
    Chrome,
    /// Safari-like fingerprint
    Webkit,
}

// Custom UnknownExtension Codec
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
