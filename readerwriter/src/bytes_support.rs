//! Reader implementation for Bytes and Buf.
//! Writer implementation for BytesMut and BufMut.

use crate::{WriteError, Writer};
use bytes::{Buf, BufMut, Bytes, BytesMut};

// impl Reader for Bytes {
//     #[inline]
//     fn read(&mut self, dst: &mut [u8]) -> Result<(), ReadError> {
//         let n = dst.len();

//         if self.len() >= n {
//             let (a, b) = self.split_at(n);
//             if n == 1 {
//                 dst[0] = a[0];
//             } else {
//                 dst.copy_from_slice(a);
//             }
//             *self = b;
//             Ok(())
//         } else {
//             Err(ReadError::InsufficientBytes)
//         }
//     }

//     #[inline]
//     fn advance(&mut self, n: usize) -> Result<(), ReadError> {
//         if self.len() >= n {
//             let (_, b) = self.split_at(n);
//             *self = b;
//             Ok(())
//         } else {
//             Err(ReadError::InsufficientBytes)
//         }
//     }

//     #[inline]
//     fn remaining_bytes(&self) -> usize {
//         self.len()
//     }
// }
