use super::{CrispError, Result};
use crate::crypto::aes_gcm::{self, compute_nonce, build_aad};
use crate::crisp::record::{Record, RecordType, RecordHeader};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum CipherSuite {
    EcdheEcdsaWithAes128GcmSha256 = 0xC02B,
}

impl TryFrom<u16> for CipherSuite {
    type Error = CrispError;

    fn try_from(value: u16) -> Result<Self> {
        match value {
            0xC02B => Ok(CipherSuite::EcdheEcdsaWithAes128GcmSha256),
            _ => Err(CrispError::Cipher(format!(
                "unsupported cipher suite: {value:#06x}"
            ))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CipherState {
    pub encrypt_key: Vec<u8>,
    pub encrypt_nonce: Vec<u8>,
    pub decrypt_key: Vec<u8>,
    pub decrypt_nonce: Vec<u8>,
    pub encrypt_seq: u64,
    pub decrypt_seq: u64,
    pub cipher_suite: CipherSuite,
}

impl CipherState {
    pub fn new(
        encrypt_key: Vec<u8>,
        encrypt_nonce: Vec<u8>,
        decrypt_key: Vec<u8>,
        decrypt_nonce: Vec<u8>,
    ) -> Self {
        Self {
            encrypt_key,
            encrypt_nonce,
            decrypt_key,
            decrypt_nonce,
            encrypt_seq: 0,
            decrypt_seq: 0,
            cipher_suite: CipherSuite::EcdheEcdsaWithAes128GcmSha256,
        }
    }

    pub fn encrypt_record(
        &mut self,
        record_type: RecordType,
        plaintext: &[u8],
    ) -> Result<Record> {
        self.encrypt_seq += 1;
        let seq = self.encrypt_seq;

        let nonce = compute_nonce(&self.encrypt_nonce, seq);

        let ciphertext_len = plaintext.len() + 16;
        let header = RecordHeader::new(record_type, ciphertext_len as u16);
        let header_bytes = header.serialize();

        let aad = build_aad(seq, &header_bytes);

        let ciphertext = aes_gcm::aes128_gcm_encrypt(
            &self.encrypt_key,
            &nonce,
            plaintext,
            &aad,
        )
        .map_err(|e| CrispError::Cipher(e.to_string()))?;

        Ok(Record {
            header,
            payload: ciphertext,
        })
    }

    pub fn decrypt_record(&mut self, record: &Record) -> Result<Vec<u8>> {
        self.decrypt_seq += 1;
        let seq = self.decrypt_seq;

        let nonce = compute_nonce(&self.decrypt_nonce, seq);
        let header_bytes = record.header.serialize();
        let aad = build_aad(seq, &header_bytes);

        aes_gcm::aes128_gcm_decrypt(
            &self.decrypt_key,
            &nonce,
            &record.payload,
            &aad,
        )
        .map_err(|e| CrispError::Cipher(e.to_string()))
    }

    pub fn reset_sequences(&mut self) {
        self.encrypt_seq = 0;
        self.decrypt_seq = 0;
    }

    pub fn update_keys(
        &mut self,
        encrypt_key: Vec<u8>,
        encrypt_nonce: Vec<u8>,
        decrypt_key: Vec<u8>,
        decrypt_nonce: Vec<u8>,
    ) {
        self.encrypt_key = encrypt_key;
        self.encrypt_nonce = encrypt_nonce;
        self.decrypt_key = decrypt_key;
        self.decrypt_nonce = decrypt_nonce;
        self.reset_sequences();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStatus {
    Initial,
    HandshakeSent,
    Established,
    Resumed,
    Closed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_suite_from_u16() {
        assert_eq!(
            CipherSuite::try_from(0xC02B).unwrap(),
            CipherSuite::EcdheEcdsaWithAes128GcmSha256
        );
        assert!(CipherSuite::try_from(0x0000).is_err());
    }

    #[test]
    fn test_cipher_state_encrypt_decrypt() {
        let key = vec![0x42u8; 16];
        let nonce = vec![0x01u8; 12];

        let mut client_cipher = CipherState::new(
            key.clone(),
            nonce.clone(),
            key.clone(),
            nonce.clone(),
        );

        let mut server_cipher = CipherState::new(
            key.clone(),
            nonce.clone(),
            key.clone(),
            nonce.clone(),
        );

        let plaintext = b"Hello CRISP cipher state!";

        let record = client_cipher
            .encrypt_record(RecordType::ApplicationData, plaintext)
            .unwrap();

        let decrypted = server_cipher.decrypt_record(&record).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_cipher_state_sequence_increment() {
        let mut state = CipherState::new(
            vec![0x42; 16],
            vec![0x01; 12],
            vec![0x42; 16],
            vec![0x01; 12],
        );

        assert_eq!(state.encrypt_seq, 0);
        let _ = state
            .encrypt_record(RecordType::ApplicationData, b"msg1")
            .unwrap();
        assert_eq!(state.encrypt_seq, 1);
        let _ = state
            .encrypt_record(RecordType::ApplicationData, b"msg2")
            .unwrap();
        assert_eq!(state.encrypt_seq, 2);
    }

    #[test]
    fn test_cipher_state_reset() {
        let mut state = CipherState::new(
            vec![0x42; 16],
            vec![0x01; 12],
            vec![0x42; 16],
            vec![0x01; 12],
        );

        state.encrypt_seq = 10;
        state.decrypt_seq = 5;
        state.reset_sequences();
        assert_eq!(state.encrypt_seq, 0);
        assert_eq!(state.decrypt_seq, 0);
    }
}
