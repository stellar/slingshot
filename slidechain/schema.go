package slidechain

const schema = `
CREATE TABLE IF NOT EXISTS blocks (
  height INTEGER NOT NULL PRIMARY KEY,
  hash BLOB NOT NULL UNIQUE,
  bits BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS snapshots (
  height INTEGER NOT NULL PRIMARY KEY,
  bits BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS pegs (
  nonce_hash BLOB NOT NULL,
  amount INTEGER,
  asset_xdr BLOB,
  recipient_pubkey BLOB NOT NULL,
  imported INTEGER NOT NULL DEFAULT 0,
  stellar_tx INTEGER NOT NULL DEFAULT 0,
  nonce_expms INTEGER NOT NULL,
  PRIMARY KEY (nonce_hash)
);

CREATE TABLE IF NOT EXISTS exports (
  txid BLOB NOT NULL PRIMARY KEY,
  exporter TEXT NOT NULL,
  amount INTEGER NOT NULL,
  asset_xdr BLOB NOT NULL,
  temp_addr TEXT NOT NULL,
  seqnum INTEGER NOT NULL,
  pegged_out INTEGER NOT NULL DEFAULT 0,
  anchor BLOB NOT NULL,
  pubkey BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS custodian (
  seed TEXT NOT NULL PRIMARY KEY,
  cursor TEXT NOT NULL DEFAULT ''
);
`
