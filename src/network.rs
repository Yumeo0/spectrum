use etherparse::err::packet::SliceError;
use etherparse::{SlicedPacket, TransportSlice, UdpHeader};
use thiserror::Error;

use crate::{NetworkPacket, PacketDirection};

#[derive(Error, Debug)]
pub enum NetworkPacketError {
    #[error("error while parsing network packet: {0}")]
    EtherparsePacketError(#[from] SliceError),
    #[error("transport layer is not present on packet")]
    TransportLayerNotPresent,
    #[error("transport layer is not udp protocol")]
    TransportLayerNotUdp,
    #[error("packet does not match the required ports")]
    IncorrectPorts,
    #[error("packet payload length is invalid: {0}")]
    InvalidPayloadLength(usize),
}

pub fn parse_network_packet(
    port_ranges: &[(u16, u16)],
    bytes: Vec<u8>,
) -> Result<NetworkPacket, NetworkPacketError> {
    let (udp, payload) = parse_udp(bytes)?;
    let direction = validate_ports(&port_ranges, udp)?;

    let length = payload.len();
    if length <= 13 {
        match length {
            1 => {
                return Ok(NetworkPacket::HandshakeRequested);
            }
            13 => {
                let conv_id = u32::from_le_bytes(payload[1..5].try_into().unwrap());
                return Ok(NetworkPacket::HandshakeEstablished(conv_id));
            }
            _ => {
                return Err(NetworkPacketError::InvalidPayloadLength(length));
            }
        }
    } else {
        Ok(NetworkPacket::SegmentData(direction, payload))
    }
}

pub fn parse_udp(data: Vec<u8>) -> Result<(UdpHeader, Vec<u8>), NetworkPacketError> {
    let packet: SlicedPacket = SlicedPacket::from_ethernet(&data)?;

    let Some(transport) = packet.transport else {
        return Err(NetworkPacketError::TransportLayerNotPresent);
    };

    let TransportSlice::Udp(udp) = transport else {
        return Err(NetworkPacketError::TransportLayerNotUdp);
    };

    Ok((udp.to_header(), udp.payload().to_vec()))
}

#[inline]
fn is_port_in_ranges(port: u16, ranges: &[(u16, u16)]) -> bool {
    ranges
        .iter()
        .any(|&(start, end)| port >= start && port <= end)
}

fn validate_ports(
    port_ranges: &[(u16, u16)],
    udp: UdpHeader,
) -> Result<PacketDirection, NetworkPacketError> {
    let (src, dest) = (udp.source_port, udp.destination_port);

    if is_port_in_ranges(src, port_ranges) {
        Ok(PacketDirection::Received)
    } else if is_port_in_ranges(dest, port_ranges) {
        Ok(PacketDirection::Sent)
    } else {
        Err(NetworkPacketError::IncorrectPorts)
    }
}
