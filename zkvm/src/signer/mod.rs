use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

pub struct PartyAwaitingHashes {
	k_i: Scalar, 
	R_i: RistrettoPoint,
}
pub struct Hash (Scalar);

pub struct PartyAwaitingNonces {
	k_i: Scalar,
	R_i: RistrettoPoint,
	R_hashes: Vec<CompressedRistretto>,
}
pub struct Nonce (CompressedRistretto);

pub struct PartyAwaitingSiglets {
	k_i: Scalar,
	R_i: RistrettoPoint,
	R_vec: Vec<CompressedRistretto>,
}
pub struct Siglet (CompressedRistretto);

pub struct Signature {
	s: Scalar,
	r: CompressedRistretto,
}

impl PartyAwaitingHashes {
	pub fn new(_transcript: &mut Transcript) -> (Self, Hash) {
		// generate ephemeral keypair (k_i, R_i) using transcript
		// make H(R_i)
		unimplemented!();
	}

	pub fn receive_hashes(self, _hashes: Vec<Hash>) -> PartyAwaitingNonces {
		// store received hashes
		unimplemented!();
	}
}

impl PartyAwaitingNonces {
	pub fn receive_nonces(self, _nonces: Vec<Nonce>) -> PartyAwaitingSiglets {
		// check stored hashes against received nonces
		// store received nonces
		unimplemented!();
	}
}

impl PartyAwaitingSiglets {
	pub fn receive_siglets(self, _siglets: Vec<Siglet>) -> Signature {
		unimplemented!();
	}
}

/*
This seems to be too simple of a protocol to require a dealer? (since it basically isn't 
doing anything past receiving and giving back the vector of messages, which you'd have to
do with the message-passing protocol anyway?)

pub struct DealerForHashes {}
pub struct DealerForNonces {} 
pub struct DealerForSiglets {}

impl DealerForHashes {
	pub fn new() -> Self {
		DealerForHashes {}
	}

	pub fn receive_hashes(self, _hashes: Vec<Hash>) -> DealerForNonces {
		unimplemented!();
	}
}

impl DealerForNonces {
	pub fn receive_nonces(self, _nonces: Vec<Nonce>) -> DealerForSiglets {
		unimplemented!();
	}
}

impl DealerForSiglets {
	pub fn receive_siglets(self, _siglets: Vec<Siglet>) -> Signature {
		unimplemented!();
	}
}
*/