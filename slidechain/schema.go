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
  amount INTEGER NOT NULL,
  asset_xdr BLOB NOT NULL,
  recipient_pubkey BLOB NOT NULL,
  expiration_ms INTEGER NOT NULL,
  imported INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (nonce_hash)
);

CREATE TABLE IF NOT EXISTS exports (
  txid BLOB NOT NULL PRIMARY KEY,
  recipient TEXT NOT NULL,
  amount INTEGER NOT NULL,
  asset_xdr BLOB NOT NULL,
  exported INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS custodian (
  seed TEXT NOT NULL PRIMARY KEY,
  cursor TEXT NOT NULL DEFAULT ''
);
`
