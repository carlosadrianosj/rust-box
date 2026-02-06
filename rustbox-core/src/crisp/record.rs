use super::{CrispError, Result};
use crate::constants::CRISP_VERSION;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordType {
    Alert = 0x15,
    ServerHandshake = 0x16,
    ApplicationData = 0x17,
    ClientHandshake = 0x19,
}

impl TryFrom<u8> for RecordType {
    type Error = CrispError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x15 => Ok(RecordType::Alert),
            0x16 => Ok(RecordType::ServerHandshake),
            0x17 => Ok(RecordType::ApplicationData),
            0x19 => Ok(RecordType::ClientHandshake),
            _ => Err(CrispError::InvalidRecordType(value)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RecordHeader {
    pub record_type: RecordType,
    pub version: u16,
    pub size: u16,
}

impl RecordHeader {
    pub const SIZE: usize = 5;

    pub fn new(record_type: RecordType, size: u16) -> Self {
        Self {
            record_type,
            version: CRISP_VERSION,
            size,
        }
    }

    pub fn serialize(&self) -> [u8; 5] {
        let mut buf = [0u8; 5];
        buf[0] = self.record_type as u8;
        buf[1..3].copy_from_slice(&self.version.to_be_bytes());
        buf[3..5].copy_from_slice(&self.size.to_be_bytes());
        buf
    }

    pub fn deserialize(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE {
            return Err(CrispError::InsufficientData {
                need: Self::SIZE,
                got: data.len(),
            });
        }

        let record_type = RecordType::try_from(data[0])?;
        let version = u16::from_be_bytes([data[1], data[2]]);
        let size = u16::from_be_bytes([data[3], data[4]]);

        if version != CRISP_VERSION {
            return Err(CrispError::InvalidVersion(version));
        }

        Ok(Self {
            record_type,
            version,
            size,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Record {
    pub header: RecordHeader,
    pub payload: Vec<u8>,
}

impl Record {
    pub fn new(record_type: RecordType, payload: Vec<u8>) -> Self {
        let header = RecordHeader::new(record_type, payload.len() as u16);
        Self { header, payload }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(RecordHeader::SIZE + self.payload.len());
        buf.extend_from_slice(&self.header.serialize());
        buf.extend_from_slice(&self.payload);
        buf
    }

    pub fn parse_multiple(data: &[u8]) -> Result<Vec<Record>> {
        let mut records = Vec::new();
        let mut offset = 0;

        while offset < data.len() {
            if offset + RecordHeader::SIZE > data.len() {
                return Err(CrispError::InsufficientData {
                    need: RecordHeader::SIZE,
                    got: data.len() - offset,
                });
            }

            let header = RecordHeader::deserialize(&data[offset..])?;
            offset += RecordHeader::SIZE;

            let payload_end = offset + header.size as usize;
            if payload_end > data.len() {
                return Err(CrispError::InsufficientData {
                    need: payload_end,
                    got: data.len(),
                });
            }

            let payload = data[offset..payload_end].to_vec();
            offset = payload_end;

            records.push(Record { header, payload });
        }

        Ok(records)
    }
}

pub fn serialize_records(records: &[Record]) -> Vec<u8> {
    let total_size: usize = records
        .iter()
        .map(|r| RecordHeader::SIZE + r.payload.len())
        .sum();

    let mut buf = Vec::with_capacity(total_size);
    for record in records {
        buf.extend_from_slice(&record.serialize());
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_header_serialize_deserialize() {
        let header = RecordHeader::new(RecordType::ClientHandshake, 256);
        let bytes = header.serialize();
        assert_eq!(bytes[0], 0x19);
        assert_eq!(bytes[1], 0xF1);
        assert_eq!(bytes[2], 0x03);
        assert_eq!(u16::from_be_bytes([bytes[3], bytes[4]]), 256);

        let parsed = RecordHeader::deserialize(&bytes).unwrap();
        assert_eq!(parsed.record_type, RecordType::ClientHandshake);
        assert_eq!(parsed.version, CRISP_VERSION);
        assert_eq!(parsed.size, 256);
    }

    #[test]
    fn test_record_serialize_deserialize() {
        let payload = vec![0x01, 0x02, 0x03, 0x04];
        let record = Record::new(RecordType::ApplicationData, payload.clone());

        let serialized = record.serialize();
        assert_eq!(serialized.len(), 5 + 4);

        let parsed = Record::parse_multiple(&serialized).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].header.record_type, RecordType::ApplicationData);
        assert_eq!(parsed[0].payload, payload);
    }

    #[test]
    fn test_parse_multiple_records() {
        let r1 = Record::new(RecordType::ServerHandshake, vec![0xAA; 10]);
        let r2 = Record::new(RecordType::ApplicationData, vec![0xBB; 20]);
        let r3 = Record::new(RecordType::Alert, vec![0xCC; 5]);

        let mut data = Vec::new();
        data.extend_from_slice(&r1.serialize());
        data.extend_from_slice(&r2.serialize());
        data.extend_from_slice(&r3.serialize());

        let records = Record::parse_multiple(&data).unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].header.record_type, RecordType::ServerHandshake);
        assert_eq!(records[0].payload.len(), 10);
        assert_eq!(records[1].header.record_type, RecordType::ApplicationData);
        assert_eq!(records[1].payload.len(), 20);
        assert_eq!(records[2].header.record_type, RecordType::Alert);
        assert_eq!(records[2].payload.len(), 5);
    }

    #[test]
    fn test_invalid_record_type() {
        let data = [0xFF, 0xF1, 0x03, 0x00, 0x01, 0x42];
        let result = Record::parse_multiple(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_version() {
        let data = [0x16, 0x00, 0x00, 0x00, 0x01, 0x42];
        let result = Record::parse_multiple(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_serialize_records() {
        let records = vec![
            Record::new(RecordType::ClientHandshake, vec![0x01; 5]),
            Record::new(RecordType::ApplicationData, vec![0x02; 10]),
        ];
        let data = serialize_records(&records);
        let parsed = Record::parse_multiple(&data).unwrap();
        assert_eq!(parsed.len(), 2);
    }
}
