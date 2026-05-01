/// GREASE values according to RFC 8701.
pub(crate) const GREASE_VALUES: [u16; 16] = [
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA,
    0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
];

/// Simple RNG seeded from session ID bytes for stable GREASE values across a handshake.
pub(crate) struct GreaseRng {
    state: u64,
}

impl GreaseRng {
    pub(crate) fn from_session_id(session_id: &[u8]) -> Self {
        let mut seed = [0u8; 8];
        let len = session_id.len().min(8);
        seed[..len].copy_from_slice(&session_id[..len]);
        Self {
            state: u64::from_be_bytes(seed),
        }
    }

    fn next_u32(&mut self) -> u32 {
        // xorshift64*
        self.state ^= self.state >> 12;
        self.state ^= self.state << 25;
        self.state ^= self.state >> 27;
        ((self.state.wrapping_mul(0x2545_F491_4F6C_DD1D)) >> 32) as u32
    }

    pub(crate) fn next_usize(&mut self, max: usize) -> usize {
        (self.next_u32() as usize) % max
    }
}

/// Pick a random GREASE value.
pub(crate) fn get_grease_value(rng: &mut GreaseRng) -> u16 {
    GREASE_VALUES[rng.next_usize(GREASE_VALUES.len())]
}
