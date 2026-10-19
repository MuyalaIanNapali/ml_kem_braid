pub trait ChunkConfig {
    fn chunk_size(&self) -> usize;
    fn needed_chunks(&self) -> usize;
    fn parity_chunks(&self) -> usize;
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HeaderConfig {
    chunk_size: usize,
    needed_chunks: usize,
    parity_chunks: usize
}

pub struct Ct1Config {
    chunk_size: usize,
    needed_chunks: usize,
    parity_chunks: usize
}

pub struct EkVectorConfig{
    chunk_size: usize,
    needed_chunks: usize,
    parity_chunks: usize
}

pub struct Ct2Config {
    chunk_size: usize,
    needed_chunks: usize,
    parity_chunks: usize
}

impl Default for HeaderConfig {
    fn default() -> Self {
        Self {
            chunk_size: 32,
            needed_chunks: 4,
            parity_chunks: 4,
        }
    }
}

impl ChunkConfig for HeaderConfig {
    fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    fn needed_chunks(&self) -> usize {
        self.needed_chunks
    }

    fn parity_chunks(&self) -> usize {
        self.parity_chunks
    }
}

impl Default for Ct1Config {
    fn default() -> Self {
        Self {
            chunk_size: 32,
            needed_chunks: 30,
            parity_chunks: 15,
        }
    }
}

impl ChunkConfig for Ct1Config {
    fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    fn needed_chunks(&self) -> usize {
        self.needed_chunks
    }

    fn parity_chunks(&self) -> usize {
        self.parity_chunks
    }
}

impl Default for EkVectorConfig {
    fn default() -> Self {
        Self {
            chunk_size: 32,
            needed_chunks: 36,
            parity_chunks: 15,
        }
    }
}

impl ChunkConfig for EkVectorConfig {
    fn chunk_size(&self) -> usize {
        self.chunk_size
    }
    fn needed_chunks(&self) -> usize {
        self.needed_chunks
    }
    fn parity_chunks(&self) -> usize {
        self.parity_chunks
    }
}

impl ChunkConfig for Ct2Config {
    fn chunk_size(&self) -> usize {
        self.chunk_size
    }
    fn needed_chunks(&self) -> usize {
        self.needed_chunks
    }
    fn parity_chunks(&self) -> usize {
        self.parity_chunks
    }
}

impl Default for Ct2Config {
    fn default() -> Self {
        Self {
            chunk_size: 32,
            needed_chunks: 5,
            parity_chunks: 5,
        }
    }
}