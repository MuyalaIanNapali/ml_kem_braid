
pub mod ml_kem_braid;


#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("state decode failed")]
    StateDecode,
    #[error("not yet implemented")]
    NotImplemented,
    #[error("message decode failed")]
    MsgDecode,
    #[error("MAC verification failed")]
    MacVerifyFailed,
    #[error("epoch not in valid range: {0}")]
    EpochOutOfRange(Epoch),
    // #[error("Encoding error: {0}")]
    // EncodingDecoding(encoding::EncodingError),
    // #[error("Serialization: {0}")]
    // Serialization(serialize::Error),
    #[error("Version mismatch after negotiation")]
    VersionMismatch,
    #[error("Minimum version")]
    MinimumVersion,
    #[error("Key jump: {0} - {1}")]
    KeyJump(u32, u32),
    #[error("Key trimmed: {0}")]
    KeyTrimmed(u32),
    #[error("Key already requested: {0}")]
    KeyAlreadyRequested(u32),
    #[error("Erroneous data received from remote party")]
    ErroneousDataReceived,
    #[error("Send key epoch decreased ({0} -> {1})")]
    SendKeyEpochDecreased(u64, u64),
    #[error("Invalid params: {0}")]
    InvalidParams(&'static str),
    #[error("Chain not available")]
    ChainNotAvailable,
    #[error("Invalid state for operation")]
    InvalidState,
}

pub type Chunk = Vec<u8>;
pub type Epoch = u64;

pub type Secret = Vec<u8>;

pub const PROTOCOL_INFO: &[u8] = b"Anon_Double_Ratchet_MLKEM768_SHA-256";

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EncodedChunk {
    chunk_idx: usize,
    chunk: Chunk,
    epoch: Epoch,
}

pub struct EpochSecret {
    pub epoch: Epoch,
    pub secret: Secret,
}




#[cfg(test)]
#[cfg(test)]
mod tests {
    use libcrux_ml_kem::mlkem768::incremental;

    #[test]
    fn print_mlkem768_key_sizes() {
        pub const CIPHERTEXT1_SIZE: usize = incremental::Ciphertext2::len();

        println!("MLKEM768 Key Sizes: {} ", CIPHERTEXT1_SIZE);
    }

}

