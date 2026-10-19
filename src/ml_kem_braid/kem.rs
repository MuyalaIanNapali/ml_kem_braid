use libcrux_ml_kem::mlkem768::incremental;
// 1. Bring TryRngCore into scope
use rand::rngs::SysRng;
use rand::TryRng;

pub const CT2_SIZE :usize= 128;

pub type Hdr = Vec<u8>;
pub type EncapsulationKey = Vec<u8>;
pub type DecapsulationKey = Vec<u8>;

pub type SharedSecret = Vec<u8>;

pub type EncapsulationState = Vec<u8>;

pub type Ciphertext1 = Vec<u8>;

pub type Ciphertext2 = Vec<u8>;

pub struct KemKeys {
    pub dk: DecapsulationKey,
    pub ek_seed: Hdr,
    pub ek_vector: EncapsulationKey,
}


// pk1 / ek_seed: 64 bytes
// pk2 / ek_vector: 1152 bytes
// sk / dk: 2400 bytes

pub fn keygen() -> KemKeys {
    let mut random = [0u8; libcrux_ml_kem::KEY_GENERATION_SEED_SIZE];

    SysRng.try_fill_bytes(&mut random)
        .expect("Failed to gather secure system entropy");

    let output = incremental::KeyPairCompressedBytes::from_seed(random);

    KemKeys {
        ek_seed: output.pk1().to_vec(),
        ek_vector: output.pk2().to_vec(),
        dk: output.sk().to_vec(),
    }
}


pub fn decaps(dk: &DecapsulationKey, ct1: &Vec<u8>, ct2: &Vec<u8>) -> SharedSecret {
    let ct1 = incremental::Ciphertext1 {
        value: ct1.as_slice().try_into().expect("size should be correct"),
    };
    let ct2 = incremental::Ciphertext2 {
        value: ct2.as_slice().try_into().expect("size should be correct"),
    };
    incremental::decapsulate_compressed_key(
        dk.as_slice().try_into().expect("size should be correct"),
        &ct1,
        &ct2,
    )
        .to_vec()
}

pub fn encaps1(
    hdr: &Vec<u8>,
) -> (Ciphertext1, EncapsulationState, SharedSecret) {
    let mut randomness = [0u8; libcrux_ml_kem::SHARED_SECRET_SIZE];
    SysRng.try_fill_bytes(&mut randomness).expect("Failed to gather secure system entropy");
    let mut state = vec![0u8; incremental::encaps_state_len()];
    let mut ss = vec![0u8; libcrux_ml_kem::SHARED_SECRET_SIZE];
    let ct1 = incremental::encapsulate1(hdr.as_slice(), randomness, &mut state, &mut ss);
    (
        ct1.expect("should only fail based on sizes, all sizes should be correct")
            .value
            .to_vec(),
        state,
        ss,
    )
}

pub fn encaps2(ek: &EncapsulationKey, es: &EncapsulationState) -> Ciphertext2 {
    let maybe_fix = potentially_fix_state_incorrectly_encoded_by_libcrux_issue_1275(es);
    let es = maybe_fix.as_ref().unwrap_or(es);
    let ct2 = incremental::encapsulate2(
        es.as_slice().try_into().expect("size should be correct"),
        ek.as_slice().try_into().expect("size should be correct"),
    );
    ct2.value.to_vec()
}


fn potentially_fix_state_incorrectly_encoded_by_libcrux_issue_1275(
    es: &EncapsulationState,
) -> Option<EncapsulationState> {
    assert_eq!(es.len(), 2080);
    // Look at each value within the error2 portion of EncapsState.
    //
    // The last 32 bytes are a raw random vector, thus they don't have endianness
    // and we shouldn't flip them.  All other bytes are encoded i16s.
    // This is the libcrux-specific encoding of the following struct, where all
    // PolynomialRingElements are encoded as described.
    //
    //    pub struct EncapsState<const K: usize, Vector: Operations> {
    //        pub(super) r_as_ntt: [PolynomialRingElement<Vector>; K],
    //        pub(super) error2: PolynomialRingElement<Vector>,
    //        pub(super) randomness: [u8; 32],
    //    }
    //
    // To determine whether it's valid or not, we look at the encoding of `error2`.
    // All error2 values should be in the range [-2, 2].
    // This is 𝜂2 from https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf
    // page 39 table 2, generated as 𝑒2 on page 30 algorithm 14 line 17.
    const NEG1_I16: i16 = 0xFFFFu16 as i16;
    const NEG2_I16_GOOD: i16 = 0xFFFEu16 as i16;
    const NEG2_I16_BAD: i16 = 0xFEFFu16 as i16;

    for c in es[1536..2080 - 32].chunks(2) {
        match i16::from_le_bytes(c.try_into().expect("chunk should be size 2")) {
            0x0000i16 | NEG1_I16 => {} // These have the same encoding for i16 in little/big-endian
            0x0001i16 | 0x0002i16 | NEG2_I16_GOOD => {
                return None;
            }
            0x0100i16 | 0x0200i16 | NEG2_I16_BAD => {
                // If they aren't in the expected range, we probably have a state with bad endian-ness.  So flip it.
                log::info!("spqr fixing bad encapsulate1 stored state endianness");
                return Some(flip_endianness_of_encapsulation_state(es));
            }
            _ => {
                // We're in a weird state, so just use what we had initially.
                log::warn!("spqr unable to fix encapsulate1 stored state endianness");
                return None;
            }
        }
    }
    None
}

fn flip_endianness_of_encapsulation_state(es: &EncapsulationState) -> EncapsulationState {
    #[allow(clippy::manual_is_multiple_of)]
    let es_len_multiple_of_2 = es.len() % 2 == 0;
    assert!(es_len_multiple_of_2);
    assert!(es.len() > 32);
    let mut fixed_es = es.clone();
    for i in (0..fixed_es.len() - 32).step_by(2) {
        (fixed_es[i], fixed_es[i + 1]) = (fixed_es[i + 1], fixed_es[i])
    }
    fixed_es
}

