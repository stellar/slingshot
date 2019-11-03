CREATE TABLE IF NOT EXISTS block_records (
  height integer PRIMARY KEY NOT NULL,
  header_json text NOT NULL,
  txs_json text NOT NULL,
  utxo_proofs_json text NOT NULL,
  state_json text NOT NULL
);

CREATE TABLE IF NOT EXISTS user_records (
  id varchar PRIMARY KEY NOT NULL,
  seed varchar NOT NULL,
  info_json text NOT NULL
);

CREATE TABLE IF NOT EXISTS asset_records (
  owner_id varchar NOT NULL,
  alias varchar NOT NULL,
  key_hex varchar NOT NULL,
  flavor_hex varchar NOT NULL,
  PRIMARY KEY (owner_id, alias)
);

CREATE TABLE IF NOT EXISTS account_records (
  owner_id varchar NOT NULL,
  alias varchar NOT NULL,
  wallet_id varchar NOT NULL,
  wallet_json text NOT NULL,
  PRIMARY KEY (owner_id, alias)
);
