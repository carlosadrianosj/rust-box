use crate::constants::CHUNK_SIZE;

/// A plaintext chunk before encryption, carrying its index and data.
#[derive(Debug, Clone)]
pub struct RawChunk {
    pub index: u32,
    pub data: Vec<u8>,
}

/// Split data into fixed-size chunks of CHUNK_SIZE (1 MB).
/// The last chunk may be smaller.
pub fn split_into_chunks(data: &[u8]) -> Vec<RawChunk> {
    data.chunks(CHUNK_SIZE)
        .enumerate()
        .map(|(i, chunk)| RawChunk {
            index: i as u32,
            data: chunk.to_vec(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_empty() {
        let chunks = split_into_chunks(&[]);
        assert!(chunks.is_empty());
    }

    #[test]
    fn test_split_small_data() {
        let data = vec![0xAA; 100];
        let chunks = split_into_chunks(&data);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].index, 0);
        assert_eq!(chunks[0].data.len(), 100);
    }

    #[test]
    fn test_split_exact_boundary() {
        let data = vec![0xBB; CHUNK_SIZE];
        let chunks = split_into_chunks(&data);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].data.len(), CHUNK_SIZE);
    }

    #[test]
    fn test_split_3_5_mb() {
        let size = CHUNK_SIZE * 3 + CHUNK_SIZE / 2; // 3.5 MB
        let data = vec![0xCC; size];
        let chunks = split_into_chunks(&data);
        assert_eq!(chunks.len(), 4);
        assert_eq!(chunks[0].data.len(), CHUNK_SIZE);
        assert_eq!(chunks[1].data.len(), CHUNK_SIZE);
        assert_eq!(chunks[2].data.len(), CHUNK_SIZE);
        assert_eq!(chunks[3].data.len(), CHUNK_SIZE / 2);
        for (i, chunk) in chunks.iter().enumerate() {
            assert_eq!(chunk.index, i as u32);
        }
    }
}
