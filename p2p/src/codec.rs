use tokio_util::codec::{Encoder, Decoder};
use bytes::{BytesMut, BufMut};
use std::io;
use std::marker::PhantomData;
use futures::io::Error;
use byteorder::{LittleEndian, ByteOrder};

pub struct MessageEncoder;

impl Encoder<Vec<u8>> for MessageEncoder {
    type Error = io::Error;

    fn encode(&mut self, item: Vec<u8>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.reserve(8 + item.len());
        dst.put(&item.len().to_le_bytes()[..]);
        dst.put(item.as_slice());
        Ok(())
    }
}

impl MessageEncoder {
    pub fn new() -> Self {
        Self {}
    }
}

pub struct MessageDecoder {
    state: DecodeState
}

impl MessageDecoder {
    pub fn new() -> Self {
        MessageDecoder { state: DecodeState::Len }
    }
}

enum DecodeState {
    Len,
    Body(usize)
}

impl Decoder for MessageDecoder {
    type Item = Vec<u8>;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.state {
            DecodeState::Len => {
                if src.len() < 8 {
                    return Ok(None);
                }
                let len_bytes = src.split_to(8);
                let len = LittleEndian::read_u64(len_bytes.as_ref()) as usize;
                self.state = DecodeState::Body(len);
                Ok(None)
            }
            DecodeState::Body(len) => {
                if src.len() < len {
                    return Ok(None);
                }
                self.state = DecodeState::Len;
                Ok(Some(Vec::from(src.split_to(len).as_ref())))
            }
        }
    }
}