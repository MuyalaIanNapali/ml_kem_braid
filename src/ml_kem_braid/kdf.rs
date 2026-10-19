use hkdf::Hkdf;
use sha2::Sha256;

use crate::{Epoch, PROTOCOL_INFO};
use crate::ml_kem_braid::kem::SharedSecret;
use crate::ml_kem_braid::util::{concatenation, epoch_to_bytes};

const ROOT_KEY_SIZE: usize = 32;
const MAC_KEY_SIZE: usize = 32;


pub fn kdf_auth(
    root_key: &[u8],
    update_key: &[u8],
    epoch: Epoch,
) -> ([u8; ROOT_KEY_SIZE], [u8; MAC_KEY_SIZE]) {

    let auth_update_info = concatenation(
        &[
            PROTOCOL_INFO,
            b":Authenticator Update",
            epoch_to_bytes(epoch).as_ref()
        ]
    );
    // HKDF-IKM = update_key
    //
    // HKDF-salt = root_key
    let hkdf = Hkdf::<Sha256>::new(
        Some(root_key),
        update_key,
    );

    // info =
    //     PROTOCOL_INFO
    //     || ":Authenticator Update"
    //     || ToBytes(epoch)
    let mut info = Vec::with_capacity(
        auth_update_info.len() + 8,
    );

    info.extend_from_slice(&*auth_update_info);
    info.extend_from_slice(&epoch.to_be_bytes());

    // 64 bytes total:
    //   first  32 = new root_key
    //   second 32 = new mac_key
    let mut output = [0u8; 64];

    hkdf.expand(&info, &mut output)
        .expect("64 bytes is valid for HKDF-SHA256");

    let mut new_root_key = [0u8; 32];
    let mut new_mac_key = [0u8; 32];

    new_root_key.copy_from_slice(&output[..32]);
    new_mac_key.copy_from_slice(&output[32..64]);

    (new_root_key, new_mac_key)
}



pub fn kdf_ok(
    shared_secret: SharedSecret,
    epoch: Epoch,
) -> SharedSecret {
    let zero_salt = [0u8; 32];

    let ok_info = concatenation(
        &[
            PROTOCOL_INFO,
            b":ML KEM BRAID KEY",
            &epoch_to_bytes(epoch).as_ref()
        ]
    );

    let hkdf = Hkdf::<Sha256>::new(
        Some(&zero_salt),
        &shared_secret,
    );

    let mut info = Vec::with_capacity(
        ok_info.len() + 8,
    );

    info.extend_from_slice(&*ok_info);
    info.extend_from_slice(&epoch.to_be_bytes());

    let mut output = [0u8; 32];

    hkdf.expand(&info, &mut output)
        .expect("32 bytes is valid for HKDF-SHA256");

    output.to_vec()
}