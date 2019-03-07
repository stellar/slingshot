pub struct Multikey{

	transcript: Transcript,
	aggregated_key: VerificationKey,
}

impl Multikey {
	pub fn new<I>(pubkeys: I) -> Self
	where I:IntoIterator<Item = VerificationKey>{	
		// create trancript
		// hash in pubkeys
		// make aggregated pubkey
		// return self
		unimplemented!()
	}

	// make a_i
	pub fn factor(&self, pubkey: &VerificationKey) -> Scalar {
		// clone the transcript
		// hash in the pubkey
		// get a_i back & return
		unimplemented!()
	}

	pub fn aggregated_key(&self) -> VerificationKey {
		self.aggregated_key
	}

}


