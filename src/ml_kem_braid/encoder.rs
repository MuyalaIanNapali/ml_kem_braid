use crate::{ EncodedChunk, Epoch};
use crate::ml_kem_braid::{gf16, matrix_utils};
use crate::ml_kem_braid::config::ChunkConfig;

pub struct Encoder {
    chunk_idx: usize,
    chunks: Vec<EncodedChunk>,
    epoch: Epoch,
}

impl Encoder {
    pub fn new(
        message: Vec<u8>,
        config: Box<dyn ChunkConfig>,
        epoch: Epoch,
    ) -> Result<Self, String> {
        let chunks = Self::encode_message(
            &message,
            config.as_ref(),
            epoch,
        )?;

        Ok(Self {
            chunk_idx: 0,
            chunks,
            epoch,
        })
    }

    fn encode_message(
        message: &[u8],
        config: &dyn ChunkConfig,
        epoch: Epoch,
    ) -> Result<Vec<EncodedChunk>, String> {
        // Kotlin:
        // require(message.size % config.chunkSize == 0)

        if config.chunk_size() == 0 {
            return Err(
                "Chunk size must not be zero".to_string()
            );
        }

        if message.len() % config.chunk_size() != 0 {
            return Err(
                "Message size must be divisible by chunk size"
                    .to_string(),
            );
        }

        // Kotlin:
        // require(config.chunkSize % 2 == 0)

        if config.chunk_size() % 2 != 0 {
            return Err(
                "Chunk size must be even for GF(2^16)"
                    .to_string(),
            );
        }

        let chunks = Self::split_into_chunks(
            message,
            config.chunk_size(),
        );

        // Kotlin:
        // val k = config.chunkSize

        let k = config.needed_chunks();

        // Number of GF(2^16) elements in each chunk.
        let field_elements_per_chunk =
            config.chunk_size() / 2;

        // Convert every data chunk from bytes
        // into GF(2^16) elements.
        let mut data_chunks =
            Vec::with_capacity(k);

        for chunk in &chunks {
            let elements =
                gf16::bytes_to_field_elements(chunk);

            data_chunks.push(elements);
        }

        // Create generator matrix.
        let generator_matrix =
            matrix_utils::create_generator_matrix(
                k,
                config.parity_chunks(),
            );

        // Generate parity chunks.
        let parity_chunks =
            Self::generate_parity(
                &data_chunks,
                &generator_matrix,
                k,
                config.parity_chunks(),
                field_elements_per_chunk,
            );

        let total_chunks =
            data_chunks.len() + parity_chunks.len();

        let mut encoded_chunks =
            Vec::with_capacity(total_chunks);

        // Original data chunks.
        for chunk in data_chunks {
            let bytes =
                gf16::field_elements_to_bytes(&chunk);

            encoded_chunks.push(EncodedChunk {
                chunk_idx: encoded_chunks.len(),
                chunk: bytes,
                epoch,
            });
        }

        // Parity chunks.
        for parity_chunk in parity_chunks {
            let bytes =
                gf16::field_elements_to_bytes(
                    &parity_chunk,
                );

            encoded_chunks.push(EncodedChunk {
                chunk_idx: encoded_chunks.len(),
                chunk: bytes,
                epoch,
            });
        }

        Ok(encoded_chunks)
    }

    fn split_into_chunks(
        message: &[u8],
        chunk_size: usize,
    ) -> Vec<Vec<u8>> {
        message
            .chunks(chunk_size)
            .map(|chunk| chunk.to_vec())
            .collect()
    }

    fn generate_parity(
        data_chunks: &[Vec<u16>],
        generator_matrix: &[Vec<u16>],
        k: usize,
        m: usize,
        field_elements_per_chunk: usize,
    ) -> Vec<Vec<u16>> {
        let mut parity_chunks =
            vec![
                vec![0u16; field_elements_per_chunk];
                m
            ];

        for p in 0..m {
            for j in 0..field_elements_per_chunk {
                let mut value = 0u16;

                for i in 0..k {
                    let coefficient =
                        generator_matrix[k + p][i];

                    let data_value =
                        data_chunks[i][j];

                    let product =
                        gf16::multiply(
                            coefficient,
                            data_value,
                        );

                    value =
                        gf16::add(value, product);
                }

                parity_chunks[p][j] = value;
            }
        }

        parity_chunks
    }

    pub fn next_chunk(
        &mut self,
    ) -> Option<EncodedChunk> {
        if self.chunk_idx >= self.chunks.len() {
            return None;
        }

        let chunk =
            self.chunks[self.chunk_idx].clone();

        self.chunk_idx += 1;

        Some(chunk)
    }

    pub fn remaining(&self) -> usize {
        self.chunks.len() - self.chunk_idx
    }

    pub fn len(&self) -> usize {
        self.chunks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }
}