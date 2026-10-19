use std::collections::HashSet;
use crate::EncodedChunk;
use crate::ml_kem_braid::{matrix_utils, gf16};
use crate::ml_kem_braid::config::ChunkConfig;

pub struct Decoder {
    chunks: Vec<EncodedChunk>,
    needed_chunks: usize,
}

impl Decoder {
    pub fn new(
        config: &dyn ChunkConfig,
    ) -> Self {
        Self {
            chunks: Vec::new(),
            needed_chunks: config.needed_chunks(),
        }
    }

    pub fn add_chunk(
        &mut self,
        chunk: EncodedChunk,
    ) -> &mut Self {
        self.chunks.push(chunk);
        self
    }

    pub fn has_message(&self) -> bool {
        let unique_indexes: HashSet<usize> = self
            .chunks
            .iter()
            .map(|chunk| chunk.chunk_idx)
            .collect();

        unique_indexes.len() >= self.needed_chunks
    }

    pub fn message(
        &self,
        config: &dyn ChunkConfig,
    ) -> Option<Vec<u8>> {
        if !self.has_message() {
            return None;
        }

        Decoder::decode(
            &self,
            config,
        ).ok()
    }

    pub fn decode(
        &self,
        config: &dyn ChunkConfig,
    ) -> Result<Vec<u8>, String> {
        if config.chunk_size() == 0 {
            return Err(
                "Chunk size must be greater than zero"
                    .to_string(),
            );
        }

        if config.chunk_size() % 2 != 0 {
            return Err(
                "Chunk size must be even for GF(2^16)"
                    .to_string(),
            );
        }

        if config.needed_chunks() == 0 {
            return Err(
                "needed_chunks must be greater than zero"
                    .to_string(),
            );
        }

        if config.parity_chunks() == 0 {
            return Err(
                "parity_chunks must be greater than zero"
                    .to_string(),
            );
        }

        let k = config.needed_chunks();
        let m = config.parity_chunks();
        let total_chunks = k + m;

        if self.chunks.len() < k {
            return Err(format!(
                "At least {k} chunks are required for decoding"
            ));
        }

        // We only need k chunks to reconstruct
        // the original k data chunks.
        let selected_chunks = &self.chunks[..k];

        // Validate chunk sizes.
        for encoded_chunk in selected_chunks {
            if encoded_chunk.chunk.len()
                != config.chunk_size()
            {
                return Err(format!(
                    "Every received chunk must have size {}",
                    config.chunk_size()
                ));
            }
        }

        // Validate indexes.
        for encoded_chunk in selected_chunks {
            if encoded_chunk.chunk_idx >= total_chunks {
                return Err(format!(
                    "Invalid chunk index: {}",
                    encoded_chunk.chunk_idx
                ));
            }
        }

        // Ensure indexes are unique.
        for i in 0..k {
            for j in (i + 1)..k {
                if selected_chunks[i].chunk_idx
                    == selected_chunks[j].chunk_idx
                {
                    return Err(
                        "Received chunk indexes must be unique"
                            .to_string(),
                    );
                }
            }
        }

        // Convert received byte chunks into GF(2^16)
        // field elements.
        let mut received_elements =
            Vec::with_capacity(k);

        for encoded_chunk in selected_chunks {
            let elements =
                gf16::bytes_to_field_elements(
                    &encoded_chunk.chunk,
                );

            received_elements.push(elements);
        }

        // Build the original generator matrix.
        //
        //       [ I ]
        // G  =  [ P ]
        //
        let generator_matrix =
            matrix_utils::create_generator_matrix(k, m);

        // Select the k rows corresponding to the
        // chunks we actually received.
        let mut selected_matrix =
            vec![vec![0u16; k]; k];

        for i in 0..k {
            let chunk_index =
                selected_chunks[i].chunk_idx;

            selected_matrix[i] =
                generator_matrix[chunk_index].clone();
        }

        // Invert the selected generator matrix.
        let inverse =
            matrix_utils::inverse(&selected_matrix);

        // Recover the original data chunks.
        //
        // original = inverse * received
        let original_elements =
            matrix_utils::multiply(
                &inverse,
                &received_elements,
            );

        // Convert GF(2^16) elements back into bytes.
        let mut original_chunks =
            Vec::with_capacity(k);

        for elements in &original_elements {
            let bytes =
                gf16::field_elements_to_bytes(
                    elements,
                );

            original_chunks.push(bytes);
        }

        // Concatenate the original chunks.
        Ok(Self::concatenate_chunks(
            &original_chunks,
        ))
    }




    fn concatenate_chunks(
        chunks: &[Vec<u8>],
    ) -> Vec<u8> {
        let total_size: usize =
            chunks.iter().map(|c| c.len()).sum();

        let mut result =
            Vec::with_capacity(total_size);

        for chunk in chunks {
            result.extend_from_slice(chunk);
        }

        result
    }
}