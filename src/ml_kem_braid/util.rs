use subtle::ConstantTimeEq;
use sha3::{Sha3_256, Digest};

pub(crate) fn constant_time_eq(
    lhs: &[u8],
    rhs: &[u8],
) -> bool {
    lhs.ct_eq(rhs).into()
}

pub fn sha3_256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();

    hasher.update(input);

    let result = hasher.finalize();

    let mut output = [0u8; 32];
    output.copy_from_slice(&result);

    output
}

pub(crate) fn concatenation(parts: &[&[u8]]) -> Box<[u8]> {
    let total_size: usize = parts
        .iter()
        .map(|part| part.len())
        .sum();

    let mut result = Vec::with_capacity(total_size);

    for part in parts {
        result.extend_from_slice(part);
    }

    result.into_boxed_slice()
}

pub(crate) fn epoch_to_bytes(epoch: u64) -> [u8; 8] {
    epoch.to_be_bytes()
}