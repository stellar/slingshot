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
  operation_num INTEGER NOT NULL,
  ledger_num INTEGER NOT NULL,
  amount INTEGER NOT NULL,
  asset_code BLOB NOT NULL, -- serialized xdr (?)
  payer_account_id TEXT NOT NULL,
  unpeg_output_id BLOB      -- NULL until sidechain issuance done
);

CREATE UNIQUE INDEX IF NOT EXISTS unpeg_output_ids ON pegs (unpeg_output_id) WHERE unpeg_output_id IS NOT NULL;
`
