//! Writer implementation for merlin::Transcript.

use crate::{WriteError, Writer};
use merlin::Transcript;

impl Writer for Transcript {
    #[inline]
    fn write(&mut self, label: &'static [u8], src: &[u8]) -> Result<(), WriteError> {
        self.append_message(label, src);
        Ok(())
    }

    #[inline]
    fn remaining_capacity(&self) -> usize {
        usize::max_value()
    }
}
