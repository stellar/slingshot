package main

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
  txid TEXT NOT NULL,
  txhash BLOB NOT NULL,
  operation_num INTEGER NOT NULL,
  amount INTEGER NOT NULL,
  asset_code BLOB NOT NULL,
  imported INTEGER NOT NULL DEFAULT 0
);
`
