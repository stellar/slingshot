use crate::cybershake::PublicKey;
use crate::peer::PeerAddr;
use crate::{PeerID, PeerMessage};
use bytes::{Buf, BufMut, BytesMut};
use curve25519_dalek::ristretto::CompressedRistretto;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use tokio_util::codec::{Decoder, Encoder};
use std::convert::TryFrom;

pub struct MessageEncoder;

impl Encoder<PeerMessage> for MessageEncoder {
    type Error = io::Error;

    fn encode(&mut self, item: PeerMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match item {
            PeerMessage::Hello(u) => {
                dst.put_u8(0); // Message type
                const HELLO_MESSAGE_LEN: u32 = 2;
                dst.put_u32(HELLO_MESSAGE_LEN);
                dst.put_u16(u);
            }
            PeerMessage::Peers(p) => {
                dst.put_u8(1); // Message type
                dst.put_u32(0); // We put here length after
                p.into_iter().for_each(|peer| {
                    encode_peer_addr(peer, dst);
                });
                let body_len = (dst.len() - 5) as u32;
                dst[1..5].copy_from_slice(&body_len.to_be_bytes()[..])
            }
            PeerMessage::Data(data) => {
                dst.put_u8(2); // Message type
                let len = u32::try_from(data.len()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, format!("Max length {} but try to put {} bytes", u32::max_value(), data.len())))?;
                dst.put_u32(len);
                dst.put(data.as_slice());
            }
        }
        Ok(())
    }
}

impl MessageEncoder {
    pub fn new() -> Self {
        Self {}
    }
}

pub struct MessageDecoder {
    state: DecodeState,
}

impl MessageDecoder {
    pub fn new() -> Self {
        MessageDecoder {
            state: DecodeState::MessageType,
        }
    }
}

enum DecodeState {
    MessageType,
    Len(u8),
    Body(u8, usize),
}

impl Decoder for MessageDecoder {
    type Item = PeerMessage;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.state {
            DecodeState::MessageType => {
                if src.is_empty() {
                    return Ok(None);
                }
                let command_type = src.get_u8();
                match command_type {
                    0..=2 => {}
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("Unknown command: {}", command_type),
                        ))
                    }
                }
                self.state = DecodeState::Len(command_type);
                self.decode(src)
            }
            DecodeState::Len(m_type) => {
                if src.len() < 4 {
                    return Ok(None);
                }
                let len = src.get_u32() as usize;
                self.state = DecodeState::Body(m_type, len);
                self.decode(src)
            }
            DecodeState::Body(m_type, len) => {
                if src.len() < len {
                    return Ok(None);
                }
                self.state = DecodeState::MessageType;
                read_message_body(m_type, len, src).map(Some)
            }
        }
    }
}

fn read_message_body(
    message_type: u8,
    len: usize,
    src: &mut BytesMut,
) -> Result<PeerMessage, io::Error> {
    match message_type {
        0 => {
            if len != 2 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Invalid length for hello message: {}", len),
                ));
            }
            let data = src.get_u16();
            Ok(PeerMessage::Hello(data))
        }
        1 => {
            let mut peers = vec![];
            let mut peers_bytes = src.split_to(len);
            while !peers_bytes.is_empty() {
                let peer = decode_peer_addr(&mut peers_bytes)?;
                peers.push(peer);
            }
            Ok(PeerMessage::Peers(peers))
        }
        2 => Ok(PeerMessage::Data(src.split_to(len).to_vec())),
        m => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Unknown message type: {}", m),
        )),
    }
}

fn encode_peer_addr(peer: PeerAddr, buf: &mut BytesMut) {
    match peer.addr {
        SocketAddr::V4(d) => {
            buf.put_u8(4);
            buf.put(&d.ip().octets()[..]);
            buf.put_u16(d.port());
        }
        SocketAddr::V6(d) => {
            buf.put_u8(6);
            buf.put(&d.ip().octets()[..]);
            buf.put_u16(d.port());
            buf.put_u32(d.flowinfo());
            buf.put_u32(d.scope_id())
        }
    }
    buf.put(peer.id.0.as_bytes());
}

fn decode_peer_addr(buf: &mut BytesMut) -> Result<PeerAddr, io::Error> {
    let addr = read_socket_addr(buf)?;
    if buf.len() < 32 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("Must be 32 bytes for key, but found {}", buf.len())));
    }
    let key = buf.split_to(32);
    let id = PeerID(PublicKey::from(CompressedRistretto::from_slice(
        key.as_ref(),
    )));
    Ok(PeerAddr { id, addr })
}

fn read_socket_addr(buf: &mut BytesMut) -> Result<SocketAddr, io::Error> {
    // We check if !buf.is_empty() in MessageDecoder::decode, so it have at least 1 byte
    let ipv = buf.get_u8();
    match ipv {
        4 => read_ipv4_addr(buf),
        6 => read_ipv6_addr(buf),
        v => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Unknown ip version: {}", v),
        )),
    }
}

const IPV4_LENGTH: usize = 4 + 2;
fn read_ipv4_addr(buf: &mut BytesMut) -> Result<SocketAddr, io::Error> {
    if buf.len() < IPV4_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!(
                "must be {} bytes for peer ipv4 addr, but found {}",
                IPV4_LENGTH,
                buf.len()
            ),
        ));
    }

    let ip = buf.get_u32();
    let port = buf.get_u16();
    let ip = Ipv4Addr::from(ip);

    Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
}

const IPV6_LENGTH: usize = 16 + 2 + 4 + 4;
fn read_ipv6_addr(buf: &mut BytesMut) -> Result<SocketAddr, io::Error> {
    if buf.len() < IPV6_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!(
                "must be {} bytes for peer ipv6 addr, but found {}",
                IPV6_LENGTH,
                buf.len()
            ),
        ));
    }

    let ip = buf.get_u128();
    let port = buf.get_u16();
    let flowinfo = buf.get_u32();
    let scope_id = buf.get_u32();
    let ip = Ipv6Addr::from(ip);

    Ok(SocketAddr::V6(SocketAddrV6::new(
        ip, port, flowinfo, scope_id,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_hello() {
        let msg = PeerMessage::Hello(20);
        let mut bytes = BytesMut::new();
        MessageEncoder::new()
            .encode(msg.clone(), &mut bytes)
            .expect("Must be encoded");
        let res = MessageDecoder::new()
            .decode(&mut bytes)
            .expect("Message must be decoded without errors")
            .expect("message must be encoded to end");

        assert_eq!(msg, res);
    }

    #[test]
    fn code_peers() {
        let msg = PeerMessage::Peers(vec![
            PeerAddr {
                id: PeerID(PublicKey::from(CompressedRistretto([0u8; 32]))),
                addr: SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from([30; 16]), 40, 12, 24)),
            },
            PeerAddr {
                id: PeerID(PublicKey::from(CompressedRistretto([0u8; 32]))),
                addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from([20; 4]), 40)),
            },
        ]);
        let mut bytes = BytesMut::new();
        MessageEncoder::new()
            .encode(msg.clone(), &mut bytes)
            .expect("Must be encoded");
        let res = MessageDecoder::new()
            .decode(&mut bytes)
            .expect("Message must be decoded without errors")
            .expect("message must be encoded to end");

        assert_eq!(msg, res);
    }
}
