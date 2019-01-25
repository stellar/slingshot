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
  operation_num INTEGER NOT NULL,
  amount INTEGER NOT NULL,
  asset_xdr BLOB NOT NULL,
  recipient_pubkey BLOB NOT NULL,
  imported INTEGER NOT NULL DEFAULT 0,
  expiration_ms INTEGER NOT NULL,
  PRIMARY KEY nonce_hash
);

CREATE TABLE IF NOT EXISTS exports (
  txid BLOB NOT NULL PRIMARY KEY,
  exporter TEXT NOT NULL,
  amount INTEGER NOT NULL,
  asset_xdr BLOB NOT NULL,
  temp TEXT NOT NULL,
  seqnum INTEGER NOT NULL,
  exported INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS custodian (
  seed TEXT NOT NULL PRIMARY KEY,
  cursor TEXT NOT NULL DEFAULT ''
);
`
