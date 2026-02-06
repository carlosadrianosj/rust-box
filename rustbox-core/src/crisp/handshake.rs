use sha2::{Sha256, Digest};

use super::{CrispError, Result};
use super::record::{Record, RecordType};
use crate::traits::random::SecureRandom;
use crate::traits::clock::Clock;

#[derive(Debug, Clone)]
pub struct ClientHello {
    pub random: Vec<u8>,
    pub timestamp: u32,
    pub ecdh_pub_key1: Vec<u8>,
    pub ecdh_pub_key2: Vec<u8>,
    pub session_ticket: Vec<u8>,
    pub psk_data: Vec<u8>,
}

impl ClientHello {
    pub fn new(
        ecdh_pub_key1: Vec<u8>,
        ecdh_pub_key2: Vec<u8>,
        session_ticket: Vec<u8>,
        rng: &dyn SecureRandom,
        clock: &dyn Clock,
    ) -> std::result::Result<Self, crate::error::RustBoxError> {
        let mut random = vec![0u8; 32];
        rng.fill_bytes(&mut random)?;

        let timestamp = clock.now_secs()? as u32;

        Ok(Self {
            random,
            timestamp,
            ecdh_pub_key1,
            ecdh_pub_key2,
            session_ticket,
            psk_data: Vec::new(),
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);

        // Fixed header
        buf.extend_from_slice(&[0x01, 0x03, 0xF1, 0x01, 0xC0, 0x2B]);

        // Random (32 bytes)
        buf.extend_from_slice(&self.random);

        // Timestamp (4 bytes, BigEndian)
        buf.extend_from_slice(&self.timestamp.to_be_bytes());

        // Extension header
        buf.extend_from_slice(&[0x00, 0x00]);

        // Extension length placeholder
        let ext_len_pos = buf.len();
        buf.extend_from_slice(&[0x00, 0x00]);

        // Key offer 1 (P256)
        buf.extend_from_slice(&[0x01, 0x00]);
        buf.extend_from_slice(&(self.ecdh_pub_key1.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.ecdh_pub_key1);

        // Key offer 2 (P256)
        buf.extend_from_slice(&[0x02, 0x00]);
        buf.extend_from_slice(&(self.ecdh_pub_key2.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.ecdh_pub_key2);

        // Session ticket
        if !self.session_ticket.is_empty() {
            buf.extend_from_slice(&(self.session_ticket.len() as u16).to_be_bytes());
            buf.extend_from_slice(&self.session_ticket);
        }

        // PSK data
        if !self.psk_data.is_empty() {
            buf.extend_from_slice(&self.psk_data);
        }

        // Fill extension length
        let ext_len = (buf.len() - ext_len_pos - 2) as u16;
        buf[ext_len_pos] = (ext_len >> 8) as u8;
        buf[ext_len_pos + 1] = (ext_len & 0xFF) as u8;

        buf
    }

    pub fn to_record(&self) -> Record {
        let payload = self.serialize();
        Record::new(RecordType::ClientHandshake, payload)
    }

    pub fn hash(&self) -> Vec<u8> {
        let data = self.serialize();
        let mut hasher = Sha256::new();
        hasher.update(&data);
        hasher.finalize().to_vec()
    }
}

#[derive(Debug, Clone)]
pub struct ServerHello {
    pub random: Vec<u8>,
    pub cipher_suite: u16,
    pub ecdh_pub_key: Vec<u8>,
    pub key_group: u32,
    pub raw: Vec<u8>,
}

impl ServerHello {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 38 {
            return Err(CrispError::Handshake("ServerHello too short".into()));
        }

        let mut offset = 0;

        // Skip fixed header (6 bytes)
        if data.len() > 6 {
            offset = 6;
        }

        // Random (32 bytes)
        if offset + 32 > data.len() {
            return Err(CrispError::Handshake("ServerHello: missing random".into()));
        }
        let random = data[offset..offset + 32].to_vec();
        offset += 32;

        // Cipher suite (2 bytes)
        let cipher_suite = if offset + 2 <= data.len() {
            u16::from_be_bytes([data[offset], data[offset + 1]])
        } else {
            0xC02B
        };
        offset += 2;

        // Parse extensions
        let mut ecdh_pub_key = Vec::new();
        let mut key_group = 1u32;

        while offset + 4 <= data.len() {
            let group = u16::from_be_bytes([data[offset], data[offset + 1]]);
            offset += 2;
            let key_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;

            if offset + key_len <= data.len() {
                ecdh_pub_key = data[offset..offset + key_len].to_vec();
                key_group = group as u32;
                let _ = offset + key_len; // consumed
                break;
            } else {
                break;
            }
        }

        Ok(Self {
            random,
            cipher_suite,
            ecdh_pub_key,
            key_group,
            raw: data.to_vec(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct EncryptedExtensions {
    pub raw: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CertificateVerify {
    pub signature: Vec<u8>,
    pub raw: Vec<u8>,
}

impl CertificateVerify {
    pub fn parse(data: &[u8]) -> Result<Self> {
        Ok(Self {
            signature: data.to_vec(),
            raw: data.to_vec(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct NewSessionTicket {
    pub lifetime: u32,
    pub ticket: Vec<u8>,
    pub mac_value: Vec<u8>,
    pub iv: Vec<u8>,
    pub raw: Vec<u8>,
}

impl NewSessionTicket {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 8 {
            return Err(CrispError::Handshake("NewSessionTicket too short".into()));
        }

        let mut offset = 0;

        let lifetime = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        offset += 4;

        if offset + 2 > data.len() {
            return Ok(Self {
                lifetime,
                ticket: Vec::new(),
                mac_value: Vec::new(),
                iv: Vec::new(),
                raw: data.to_vec(),
            });
        }
        let ticket_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        let ticket = if offset + ticket_len <= data.len() {
            let t = data[offset..offset + ticket_len].to_vec();
            offset += ticket_len;
            t
        } else {
            data[offset..].to_vec()
        };

        let remaining = if offset < data.len() {
            data[offset..].to_vec()
        } else {
            Vec::new()
        };

        let (mac_value, iv) = if remaining.len() >= 28 {
            (remaining[..16].to_vec(), remaining[16..28].to_vec())
        } else {
            (remaining.clone(), Vec::new())
        };

        Ok(Self {
            lifetime,
            ticket,
            mac_value,
            iv,
            raw: data.to_vec(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct Finished {
    pub verify_data: Vec<u8>,
}

impl Finished {
    pub fn new(verify_data: Vec<u8>) -> Self {
        Self { verify_data }
    }

    pub fn parse(data: &[u8]) -> Self {
        Self {
            verify_data: data.to_vec(),
        }
    }
}

pub fn build_early_data_extension(psk_data: &[u8]) -> Vec<u8> {
    let mut ext = Vec::new();
    ext.extend_from_slice(&[0x00, 0x00, 0x00]);
    let len = psk_data.len() as u16;
    ext.extend_from_slice(&len.to_be_bytes());
    ext.extend_from_slice(psk_data);
    ext
}

pub fn compute_transcript_hash(messages: &[&[u8]]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    for msg in messages {
        hasher.update(msg);
    }
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::RustBoxError;

    struct TestRng;
    impl SecureRandom for TestRng {
        fn fill_bytes(&self, dest: &mut [u8]) -> std::result::Result<(), RustBoxError> {
            for b in dest.iter_mut() {
                *b = 0xAA;
            }
            Ok(())
        }
    }

    struct TestClock;
    impl Clock for TestClock {
        fn now_secs(&self) -> std::result::Result<u64, RustBoxError> {
            Ok(1700000000)
        }
        fn now_millis(&self) -> std::result::Result<u64, RustBoxError> {
            Ok(1700000000000)
        }
    }

    #[test]
    fn test_client_hello_serialize() {
        let ch = ClientHello::new(
            vec![0x04; 65],
            vec![0x04; 65],
            vec![],
            &TestRng,
            &TestClock,
        )
        .unwrap();

        let data = ch.serialize();
        assert_eq!(&data[0..6], &[0x01, 0x03, 0xF1, 0x01, 0xC0, 0x2B]);
        assert_eq!(data[6..38].len(), 32);
    }

    #[test]
    fn test_client_hello_to_record() {
        let ch = ClientHello::new(
            vec![0x04; 65],
            vec![0x04; 65],
            vec![],
            &TestRng,
            &TestClock,
        )
        .unwrap();

        let record = ch.to_record();
        assert_eq!(record.header.record_type, RecordType::ClientHandshake);
        assert_eq!(record.header.version, 0xF103);
    }

    #[test]
    fn test_transcript_hash() {
        let msg1 = [0x01, 0x02, 0x03];
        let msg2 = [0x04, 0x05, 0x06];

        let hash = compute_transcript_hash(&[&msg1, &msg2]);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_finished() {
        let verify_data = vec![0xAA; 32];
        let finished = Finished::new(verify_data.clone());
        assert_eq!(finished.verify_data, verify_data);
    }

    #[test]
    fn test_new_session_ticket_parse() {
        let mut data = Vec::new();
        data.extend_from_slice(&3600u32.to_be_bytes());
        data.extend_from_slice(&8u16.to_be_bytes());
        data.extend_from_slice(&[0xAA; 8]);
        data.extend_from_slice(&[0xBB; 16]);
        data.extend_from_slice(&[0xCC; 12]);

        let ticket = NewSessionTicket::parse(&data).unwrap();
        assert_eq!(ticket.lifetime, 3600);
        assert_eq!(ticket.ticket, vec![0xAA; 8]);
    }
}
