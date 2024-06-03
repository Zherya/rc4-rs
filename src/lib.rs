//! # RC4 cipher implementation
//!
//! NOTE: RC4 cipher is known to be cryptographically weak,
//! and should not be used in security-sensitive scenarios.

/// Represents RC4 cipher state with provided methods for data
/// encryption and decryption.
pub struct RC4 {
    /// Permutations array for `x -> state[x]` permutation.
    state: [u8; 256],

    /// The first counter, participated in Pseudo-random
    /// generation algorithm (PRGA), used for cipher
    /// keystream/gamma generation.
    i: u8,
    /// The second counter, participated in Pseudo-random
    /// generation algorithm (PRGA), used for cipher
    /// keystream/gamma generation.
    j: u8,
}

impl RC4 {
    /// Returns new `RC4` instance with ready-to-use state.
    ///
    /// Ready-to-use state means that while creating RC4 instance,
    /// Key-scheduling algorithm (KSA) is performed, so the RC4 is
    /// ready to generate keystream/bytes of gamma from provided `key`.
    ///
    /// Generally, the key can be any length between 1 and 256 bytes,
    /// but it is recommended to use maximum length to provide better
    /// security, although RC4 is cryptographically weak anyway.
    ///
    /// Keys larger than 256 bytes are also may be passed, but only
    /// first 256 bytes will be used.
    ///
    /// # Arguments
    ///
    /// * `key` - the slice of bytes used as RC4 cipher key.
    ///
    /// # Examples
    ///
    /// ```rust
    /// // Running RC4 cipher on a test vector from Wikipedia:
    /// // https://en.wikipedia.org/wiki/RC4#Test_vectors
    /// let mut rc4 = rc4_rs::RC4::new("Key".as_bytes());
    ///
    /// let mut data = Vec::from("Plaintext");
    /// rc4.xor_keystream_with(&mut data);
    ///
    /// let ciphertext = [0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3];
    /// assert_eq!(data.as_slice(), ciphertext);
    /// ```
    pub fn new(key: &[u8]) -> Self {
        let mut rc4 = Self {
            state: [0; 256],
            i: 0,
            j: 0,
        };

        // Perform Key-scheduling algorithm (KSA)
        rc4.key_scheduling_algorithm(key);

        rc4
    }

    /// Applies Key-scheduling algorithm (KSA) on RC4 instance,
    /// using provided `key`. After KSA is performed, RC4 is ready
    /// to generate keystream/bytes of gamma from the provided `key`.
    ///
    /// # Arguments
    ///
    /// * `key` - the slice of bytes used as RC4 cipher key.
    fn key_scheduling_algorithm(&mut self, key: &[u8]) {
        for (index, state) in self.state.iter_mut().enumerate() {
            *state = index as u8;
        }

        // In KSA algorithm we have to iterate over all state
        // values, and there are only 256 values, but we cannot
        // directly use iterator over it, because we swap states
        // at each iteration, and borrow checker doesn't allow
        // swapping values while iterating over it.
        // Also, key length might be less than 256 bytes, and we
        // need a cycle around the key in that case.
        // So let's combine an iterator over 256 values and
        // an iterator over cycling key.
        let mut j: u8 = 0;
        let state_index_range = 0..256;
        // zip() combines to iterators together, returning None, if either
        // iterator returns None. In our case it ends when 256 iterations are passed,
        // because the second iterator is an endless key cycle
        for (i, key) in state_index_range.zip(key.iter().cycle()) {
            // In release mode compilation, if overflow occurs,
            // Rust performs two’s complement wrapping. It is what we
            // needed here according to KSA definition, but in Rust,
            // relying on integer overflow’s wrapping behavior is
            // considered an error. So we use wrapping_add() to
            // explicitly expect modular arithmetic
            j = j.wrapping_add(self.state[i]).wrapping_add(*key);
            // Swap the values of permutations state
            self.state.swap(i, j as usize);
        }
    }

    /// Modifies RC4 state and returns new byte of the keystream/gamma,
    /// using Pseudo-random generation algorithm (PRGA).
    fn pseudo_random_generation(&mut self) -> u8 {
        self.i = self.i.wrapping_add(1);
        // j = (j + state[i]) mod 256:
        // Array cannot be indexed using u8 type indexes,
        // so self.i should be cast to usize
        self.j = self.j.wrapping_add(self.state[self.i as usize]);

        self.state.swap(self.i as usize, self.j as usize);

        let keystream_index = self.state[self.i as usize].wrapping_add(self.state[self.j as usize]);

        self.state[keystream_index as usize]
    }

    /// Continuously applies keystream bytes to the bytes of the
    /// provided `data`, XORing each `data` byte with keystream
    /// byte.
    ///
    /// # Arguments
    /// * `data` - bytes slice for applying keystream to.
    pub fn xor_keystream_with(&mut self, data: &mut [u8]) {
        data.iter_mut().for_each(|byte| {
            *byte ^= self.pseudo_random_generation();
        });
    }
}
