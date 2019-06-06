use core::mem;

#[derive(Clone,Default)]
pub(super) struct Bitarray {
    words: Vec<u64>
}

impl Bitarray {
    /// Capacity is in bits
    pub(super) fn with_capacity(cap: usize) -> Self {
        Self {
            words: Vec::with_capacity((cap+64-1)/64)
        }   
    }

    pub(super) fn count_ones(&self) -> usize {
        // FIXME: use appropriate method on u64.
        self.iter().map(|x| if x { 1usize } else { 0 } ).sum()
    }

    pub(super) fn memory(&self) -> usize {
        self.words.capacity() * mem::size_of::<u64>()
    }

    /// Returns the boolean value of the bit at a given offset.
    pub(super) fn bit_at(&self,offset: usize) -> bool {
        let word_idx = offset / 64;
        let bit_idx = offset % 64;
        if word_idx >= self.words.len() {
            return false;
        }
        ((self.words[word_idx] >> bit_idx) & 1) == 1
    }

    /// Sets bit at bit offset, extending the array as needed. 
    pub(super) fn set_bit_at(&mut self, offset: usize, bit: bool) {
        let word_idx = offset / 64;
        let bit_idx = offset % 64;
        if word_idx >= self.words.len() {
            self.words.resize(word_idx+1, 0u64);
        }
        let mask = (1 as u64) << bit_idx; // ...0001000...
        if bit {
            // set bit
            self.words[word_idx] = self.words[word_idx] | mask;
        } else {
            // clear bit
            self.words[word_idx] = self.words[word_idx] & (!mask);
        }
    }
    /// Truncates the bitarray to `len` bits.
    /// Excess bits are explicitly cleared.
    pub(super) fn truncate(&mut self, len: usize) {
        let words_len = (len + 64 - 1) / 64;
        self.words.truncate(len);
        let remainder_bits = words_len*64 - len;
        for i in 64-remainder_bits .. 64 {
            self.set_bit_at((words_len-1)*64 + i, false);
        }
    }
    
    /// Iterates all the bits as booleans
    pub(super) fn iter(&self) -> impl Iterator<Item=bool> + '_ {
        self.words.iter().flat_map(|word| {
            (0..64).map(|bit| (word >> bit) & 1u64 == 1u64 )
        })
    }

    /// Clears all the bits
    pub(super) fn clear(&mut self) {
        for word in self.words.iter_mut() {
            *word = 0;
        }
    }

    // /// Iterates over 1 bits, returning a position for each bit = 1.
    // /// Skips over all-zero words.
    // fn ones(&self) -> impl Iterator<Item=usize> + '_ {
    //     self.words.iter().enumerate().flat_map(|(i,&word)| {
    //         if word == 0 {
    //             0..0
    //         } else {
    //             0..64
    //         }.scan((), |_,j| {
    //             if (word >> i) & 1 == 1 {
    //                 Some(i*64 + j)
    //             } else {
    //                 None
    //             }
    //         })
    //     })
    // }

    // /// Iterates over ones that were added in the updated bitarray but absent in the first one.
    // fn xor_iter<'a>(&'a self, updated: &'a Self) -> impl Iterator<Item=usize> + 'a {
    //     self.words.iter().zip(updated.words.iter()).enumerate().flat_map(|(i,(&word1, &word2))| {
    //         let word = word1 ^ word2;
    //         if word == 0 {
    //             0..0
    //         } else {
    //             0..64
    //         }.scan((), |_,j| {
    //             if (word >> i) & 1 == 1 {
    //                 Some(i*64 + j)
    //             } else {
    //                 None
    //             }
    //         })
    //     })
    // }
}

#[cfg(test)]
mod tests {
    use super::*;
        
    #[test]
    fn bit_array() {

    }
}
