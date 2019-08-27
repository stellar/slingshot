CREATE TABLE IF NOT EXISTS block_records (
  height integer PRIMARY KEY NOT NULL,
  block_json text NOT NULL,
  state_json text NOT NULL
);

CREATE TABLE IF NOT EXISTS asset_records (
  alias varchar PRIMARY KEY NOT NULL,
  key_json text NOT NULL
);

CREATE TABLE IF NOT EXISTS node_records (
  alias varchar PRIMARY KEY NOT NULL,
  state_json text NOT NULL
);

