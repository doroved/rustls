use rand::Rng;

// GREASE values according to RFC 8701
// |Hex pair   |Decimal|
// |-----------|-------|
// |0x0A0A     |2570   |
// |0x1A1A     |6682   |
// |0x2A2A     |10794  |
// |0x3A3A     |14906  |
// |0x4A4A     |19018  |
// |0x5A5A     |23130  |
// |0x6A6A     |27242  |
// |0x7A7A     |31354  |
// |0x8A8A     |35466  |
// |0x9A9A     |39578  |
// |0xAAAA     |43690  |
// |0xBABA     |47802  |
// |0xCACA     |51914  |
// |0xDADA     |56026  |
// |0xEAEA     |60138  |
// |0xFAFA     |64250  |

pub(crate) const GREASE_VALUES: [u16; 16] = [
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
];

pub(crate) fn get_grease_value<R: Rng>(rng: &mut R) -> u16 {
    let index = rng.random_range(0..GREASE_VALUES.len());
    GREASE_VALUES[index]
}
