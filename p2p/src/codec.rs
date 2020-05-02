use crate::cybershake::PublicKey;
use crate::peer::PeerAddr;
use crate::{PeerID, PeerMessage};
use bytes::{Buf, BufMut, BytesMut};
use curve25519_dalek::ristretto::CompressedRistretto;
use readerwriter::Codable;
use std::io;
use std::marker::PhantomData;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use tokio_util::codec::{Decoder, Encoder};

pub struct MessageEncoder<T: Codable> {
    marker: PhantomData<T>,
}

impl<T: Codable> Encoder<PeerMessage<T>> for MessageEncoder<T> {
    type Error = io::Error;

    fn encode(&mut self, item: PeerMessage<T>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match item {
            PeerMessage::Hello(u) => {
                dst.put_u8(0); // Message type
                const HELLO_MESSAGE_LEN: u32 = 2;
                dst.put_u32_le(HELLO_MESSAGE_LEN);
                dst.put_u16_le(u);
            }
            PeerMessage::Peers(p) => {
                dst.put_u8(1); // Message type
                dst.put_u32_le(0); // We put here length after
                p.into_iter().for_each(|peer| {
                    encode_peer_addr(peer, dst);
                });
                let body_len = (dst.len() - 5) as u32;
                dst[1..5].copy_from_slice(&body_len.to_le_bytes()[..])
            }
            PeerMessage::Data(data) => {
                dst.put_u8(2); // Message type
                dst.put_u32_le(0); // We put here length after
                data.encode(dst).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("An error occured when encode body: {}", e),
                    )
                })?;
                let body_len = (dst.len() - 5) as u32;
                dst[1..5].copy_from_slice(&body_len.to_le_bytes()[..]);
            }
        }
        Ok(())
    }
}

impl<T: Codable> MessageEncoder<T> {
    pub fn new() -> Self {
        Self {
            marker: PhantomData,
        }
    }
}

pub struct MessageDecoder<T: Codable> {
    state: DecodeState,
    marker: PhantomData<T>,
}

impl<T: Codable> MessageDecoder<T> {
    pub fn new() -> Self {
        MessageDecoder {
            state: DecodeState::MessageType,
            marker: PhantomData,
        }
    }
}

#[derive(Debug, PartialEq)]
enum DecodeState {
    MessageType,
    Len(u8),
    Body(u8, usize),
}

impl<T: Codable> Decoder for MessageDecoder<T> {
    type Item = PeerMessage<T>;
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
                let len = src.get_u32_le() as usize;
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

fn read_message_body<T: Codable>(
    message_type: u8,
    len: usize,
    src: &mut BytesMut,
) -> Result<PeerMessage<T>, io::Error> {
    match message_type {
        0 => {
            if len != 2 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Invalid length for hello message: {}", len),
                ));
            }
            let data = src.get_u16_le();
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
        2 => {
            let body = src.split_to(len);
            match T::decode(&mut body.freeze()) {
                Ok(data) => Ok(PeerMessage::Data(data)),
                Err(e) => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("An error occurred when decode body: {}", e),
                )),
            }
        }
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
            buf.put_u16_le(d.port());
        }
        SocketAddr::V6(d) => {
            buf.put_u8(6);
            buf.put(&d.ip().octets()[..]);
            buf.put_u16_le(d.port());
            buf.put_u32_le(d.flowinfo());
            buf.put_u32_le(d.scope_id())
        }
    }
    buf.put(peer.id.0.as_bytes());
}

fn decode_peer_addr(buf: &mut BytesMut) -> Result<PeerAddr, io::Error> {
    let addr = read_socket_addr(buf)?;
    check_length(buf, 32, "peer id")?;
    let key = buf.split_to(32);
    let id = PeerID(PublicKey::from(CompressedRistretto::from_slice(
        key.as_ref(),
    )));
    Ok(PeerAddr { id, addr })
}

fn read_socket_addr(buf: &mut BytesMut) -> Result<SocketAddr, io::Error> {
    check_length(buf, 1, "socket addr")?;
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
    check_length(buf, IPV4_LENGTH, "ipv4")?;

    let ip = buf.get_u32_le();
    let port = buf.get_u16_le();
    let ip = Ipv4Addr::from(ip);

    Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
}

const IPV6_LENGTH: usize = 16 + 2 + 4 + 4;
fn read_ipv6_addr(buf: &mut BytesMut) -> Result<SocketAddr, io::Error> {
    check_length(buf, IPV6_LENGTH, "ipv6")?;

    let ip = buf.get_u128();
    let port = buf.get_u16_le();
    let flowinfo = buf.get_u32_le();
    let scope_id = buf.get_u32_le();
    let ip = Ipv6Addr::from(ip);

    Ok(SocketAddr::V6(SocketAddrV6::new(
        ip, port, flowinfo, scope_id,
    )))
}

fn check_length(buf: &mut BytesMut, len: usize, label: &str) -> Result<(), io::Error> {
    if buf.len() < len {
        Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!(
                "Expected {} bytes for {}, but found {}",
                len,
                label,
                buf.len()
            ),
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reexport::{BufMut, Bytes, BytesMut};
    use readerwriter::{Codable, Decodable, Encodable, Reader, Writer};
    use std::convert::Infallible;
    use std::ops::Deref;

    #[derive(Debug, Clone, PartialEq)]
    pub struct Message(pub Vec<u8>);

    impl Deref for Message {
        type Target = Vec<u8>;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl Encodable for Message {
        type Error = Infallible;

        fn encode(&self, dst: &mut impl Writer) -> Result<(), Self::Error> {
            Ok(dst.write(b"data", self.as_slice()).unwrap())
        }

        fn encoded_length(&self) -> usize {
            self.len()
        }
    }

    impl Decodable for Message {
        type Error = Infallible;

        fn decode(buf: &mut impl Reader) -> Result<Self, Self::Error> {
            Ok(Self(buf.read_vec(buf.remaining_bytes()).unwrap()))
        }
    }

    #[test]
    fn code_hello() {
        let msg = PeerMessage::<Message>::Hello(20);
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
        let msg = PeerMessage::<Message>::Peers(vec![
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

    #[test]
    fn code_custom() {
        let msg = PeerMessage::Data(Message(vec![1, 2, 3, 4, 5, 6]));
        let mut bytes = BytesMut::new();

        let mut encoder = MessageEncoder::new();
        let mut decoder = MessageDecoder::new();

        encoder
            .encode(msg.clone(), &mut bytes)
            .expect("Must be encoded");
        let res = decoder
            .decode(&mut bytes)
            .expect("Message must be decoded without errors")
            .expect("message must be encoded to end");

        assert_eq!(msg, res);
        assert_eq!(decoder.state, DecodeState::MessageType);
        assert!(bytes.is_empty())
    }
}
