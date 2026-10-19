
pub const REDUCTION_POLYNOMIAL: u16 = 0x100B;
pub const FIELD_MASK: u16 = 0xFFFF;

pub fn inverse(a: u16) -> u16{
    pow(a,65534)
}

pub fn add(a: u16, b: u16) -> u16 {
    a ^ b & FIELD_MASK
}

pub fn multiply(
    a_input: u16,
    b_input: u16,
) -> u16 {
    let mut a = a_input;
    let mut b = b_input;
    let mut result = 0u16;

    for _ in 0..16 {
        if b & 1 != 0 {
            result ^= a;
        }

        let carry = a & 0x8000 != 0;

        a <<= 1;

        if carry {
            a ^= REDUCTION_POLYNOMIAL;
        }

        b >>= 1;
    }

    result & FIELD_MASK
}

pub fn pow(
    mut b: u16,
    mut e: u32,
) -> u16 {
    let mut result = 1u16;

    while e > 0 {
        if e & 1 != 0 {
            result = multiply(result, b);
        }

        b = multiply(b, b);
        e >>= 1;
    }

    result
}

pub fn bytes_to_field_elements(
    bytes: &[u8],
) -> Vec<u16> {
    assert!(
        bytes.len() % 2 == 0,
        "Byte array size must be even for GF(2^16)"
    );

    bytes
        .chunks_exact(2)
        .map(|chunk| {
            u16::from_be_bytes([
                chunk[0],
                chunk[1],
            ])
        })
        .collect()
}

pub fn field_elements_to_bytes(
    elements: &[u16],
) -> Vec<u8> {
    let mut bytes =
        Vec::with_capacity(elements.len() * 2);

    for &element in elements {
        bytes.extend_from_slice(
            &element.to_be_bytes()
        );
    }

    bytes
}