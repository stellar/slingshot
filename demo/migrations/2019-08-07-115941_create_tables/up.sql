CREATE TABLE IF NOT EXISTS nodes (
  alias varchar PRIMARY KEY NOT NULL,
  state text NOT NULL
);

CREATE TABLE IF NOT EXISTS blocks (
  height integer PRIMARY KEY NOT NULL,
  block text NOT NULL
);
