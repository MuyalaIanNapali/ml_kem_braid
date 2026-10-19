use crate::Epoch;
use crate::ml_kem_braid::kdf::kdf_auth;
use crate::ml_kem_braid::util::constant_time_eq;
use libcrux_hmac::{hmac, Algorithm};

pub type Mac = Vec<u8>;

pub const MAC_SIZE: usize = 32;

const HEADER_INFO: &[u8] =
    b"ML_KEM_BRAID:ekheader";

const CIPHERTEXT_INFO: &[u8] =
    b"ML_KEM_BRAID:ciphertext";

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Authenticator {
    root_key: [u8; 32],
    mac_key: [u8; 32],
}

impl Authenticator {
    pub fn new(
        auth_key: &[u8],
        epoch: Epoch,
    ) -> Self {
        let mut state = Self {
            root_key: [0u8; 32],
            mac_key: [0u8; 32],
        };

        state.update(epoch, auth_key);

        state
    }

    pub fn update(
        &mut self,
        epoch: Epoch,
        key: &[u8],
    ) {
        let (root_key, mac_key) =
            kdf_auth(
                &self.root_key,
                key,
                epoch,
            );

        self.root_key = root_key;
        self.mac_key = mac_key;
    }

    pub fn mac_hdr(
        &self,
        epoch: Epoch,
        hdr: &[u8],
    ) -> Mac {
        self.mac(
            HEADER_INFO,
            epoch,
            hdr,
        )
    }

    pub fn mac_ct(
        &self,
        epoch: Epoch,
        ct: &[u8],
    ) -> Mac {
        self.mac(
            CIPHERTEXT_INFO,
            epoch,
            ct,
        )
    }

    fn mac(
        &self,
        domain: &[u8],
        epoch: Epoch,
        data: &[u8],
    ) -> Mac {
        let mut message =
            Vec::with_capacity(
                domain.len()
                    + 8
                    + data.len()
            );

        message.extend_from_slice(domain);
        message.extend_from_slice(
            &epoch.to_be_bytes()
        );
        message.extend_from_slice(data);

        hmac(
            Algorithm::Sha256,
            &self.mac_key,
            &message,
            Some(MAC_SIZE),
        )
    }

    pub fn verify_hdr(
        &self,
        epoch: Epoch,
        hdr: &[u8],
        expected_mac: &[u8],
    ) -> bool {
        let actual =
            self.mac_hdr(epoch, hdr);

        constant_time_eq(
            &actual,
            expected_mac,
        )
    }

    pub fn verify_ct(
        &self,
        epoch: Epoch,
        ct: &[u8],
        expected_mac: &[u8],
    ) -> bool {
        let actual =
            self.mac_ct(epoch, ct);

        constant_time_eq(
            &actual,
            expected_mac,
        )
    }
}