use std::fmt;
use std::time::SystemTime;

use crc32fast::hash;
use miniz_oxide::inflate::DecompressError;
use thiserror::Error;

use crate::crypto::{CryptoError, decrypt_payload, requires_crypto};
use crate::game::message::MessageId;
use crate::utility::{decompress, requires_decompression};

pub mod message;
pub mod proto;

const MIN_GAME_PACKET_HEADER_LEN: usize = 14;

#[derive(Error, Debug)]
pub enum GamePacketError {
    #[error("packet header must be at least {expected} bytes, but was {actual}")]
    HeaderTooShort { expected: usize, actual: usize },
    #[error("invalid packet type {actual}. Expected one of: 1, 2, 4, 17, 18, 20")]
    InvalidPacketType { actual: u8 },
    #[error("unexpected packet size. Expected {expected} bytes, but got {actual}")]
    PacketTooShort { expected: usize, actual: usize },
    #[error("game packet CRC mismatch")]
    CrcMismatch { expected: u32, actual: u32 },
    #[error("failed to decompress packet payload: {0}")]
    DecompressError(DecompressError),
    #[error(transparent)]
    CryptoError(#[from] CryptoError),
}

impl From<DecompressError> for GamePacketError {
    fn from(e: DecompressError) -> Self {
        GamePacketError::DecompressError(e)
    }
}

#[derive(Clone)]
pub struct GamePacket {
    pub size: usize,
    pub msg_type: u8,
    pub seq_no: u32,
    pub rpc_id: Option<u16>,
    pub msg_id: u16,
    pub crc: u32,
    pub raw_msg: Vec<u8>,
    pub timestamp: SystemTime,
}

impl GamePacket {
    pub fn try_new(data: Vec<u8>, session_key: Option<&[u8; 32]>) -> Result<Self, GamePacketError> {
        if data.len() < MIN_GAME_PACKET_HEADER_LEN {
            return Err(GamePacketError::HeaderTooShort {
                expected: MIN_GAME_PACKET_HEADER_LEN,
                actual: data.len(),
            });
        }

        let size = u16::from_le_bytes([data[0], data[1]]) as usize + 3;
        if data.len() < size {
            return Err(GamePacketError::PacketTooShort {
                expected: size,
                actual: data.len(),
            });
        }

        let msg_type = data[3];

        let seq_no = u32::from_le_bytes(data[4..8].try_into().unwrap());

        let rpc_id = match msg_type {
            4 | 20 => None,
            _ => Some(u16::from_le_bytes(data[8..10].try_into().unwrap())),
        };

        let (msg_id_offset, crc_offset, raw_offset) = match msg_type {
            1 | 2 => (10, 12, 16),
            4 => (8, 10, 14),
            17 | 18 => (10, 12, 20),
            20 => (8, 10, 18),
            _ => return Err(GamePacketError::InvalidPacketType { actual: msg_type }),
        };

        let msg_id = u16::from_le_bytes(data[msg_id_offset..msg_id_offset + 2].try_into().unwrap());
        let crc = u32::from_le_bytes(data[crc_offset..crc_offset + 4].try_into().unwrap());

        let mut raw_msg = data[raw_offset..size].to_vec();

        let actual_crc = hash(&raw_msg);
        if actual_crc != crc {
            return Err(GamePacketError::CrcMismatch {
                expected: crc,
                actual: actual_crc,
            });
        }

        if requires_crypto(msg_id) {
            if let Some(session_key) = session_key {
                raw_msg =
                    decrypt_payload(seq_no, session_key, raw_msg.into_boxed_slice())?.into_vec();
            } else {
                return Err(GamePacketError::CryptoError(CryptoError::MissingSessionKey));
            }
        }

        if requires_decompression(msg_type) {
            raw_msg = decompress(raw_msg)?;
        }

        Ok(GamePacket {
            size,
            msg_type,
            seq_no,
            rpc_id,
            msg_id,
            crc,
            raw_msg,
            timestamp: SystemTime::now(),
        })
    }

    pub fn get_msg_name(&self) -> Option<&str> {
        MessageId::try_from(self.msg_id).ok().map(|id| id.into())
    }

    pub fn parse_proto<T: protobuf::Message>(&self) -> protobuf::Result<T> {
        T::parse_from_bytes(&self.raw_msg)
    }
}

impl fmt::Debug for GamePacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GamePacket")
            .field("size", &self.size)
            .field("msg_type", &self.msg_type)
            .field("msg_id", &self.msg_id)
            .field("msg_name", &self.get_msg_name())
            .field("seq_no", &self.seq_no)
            .field("rpc_id", &self.rpc_id)
            .field("crc", &self.crc)
            .field("timestamp", &self.timestamp)
            .finish()
    }
}
