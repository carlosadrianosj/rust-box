/// A decrypted chunk ready for reassembly.
#[derive(Debug, Clone)]
pub struct DecryptedChunk {
    pub index: u32,
    pub data: Vec<u8>,
}

/// Reassemble chunks into the original data by sorting by index and concatenating.
pub fn reassemble_chunks(chunks: &[DecryptedChunk]) -> Vec<u8> {
    let mut sorted: Vec<&DecryptedChunk> = chunks.iter().collect();
    sorted.sort_by_key(|c| c.index);

    let total_size: usize = sorted.iter().map(|c| c.data.len()).sum();
    let mut result = Vec::with_capacity(total_size);
    for chunk in sorted {
        result.extend_from_slice(&chunk.data);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reassemble_empty() {
        let result = reassemble_chunks(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_reassemble_single() {
        let chunks = vec![DecryptedChunk {
            index: 0,
            data: vec![1, 2, 3],
        }];
        let result = reassemble_chunks(&chunks);
        assert_eq!(result, vec![1, 2, 3]);
    }

    #[test]
    fn test_reassemble_out_of_order() {
        let chunks = vec![
            DecryptedChunk { index: 2, data: vec![7, 8, 9] },
            DecryptedChunk { index: 0, data: vec![1, 2, 3] },
            DecryptedChunk { index: 1, data: vec![4, 5, 6] },
        ];
        let result = reassemble_chunks(&chunks);
        assert_eq!(result, vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
    }
}
