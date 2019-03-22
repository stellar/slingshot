use super::UTXO;

pub struct BCState {
    pub initial: &BlockHeader,
    pub tip: &BlockHeader,
    pub utxos: HashSet<UTXO>,
    pub nonces: VecDeque<([u8; 32], i64)>,
    pub ref_ids: VecDeque<BlockID>
}
