CREATE TABLE IF NOT EXISTS addresses (
  address TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  domain TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_jwt_iat INTEGER
);

CREATE TABLE IF NOT EXISTS mails (
  id TEXT PRIMARY KEY,
  address TEXT NOT NULL,
  sender TEXT NOT NULL,
  recipient TEXT NOT NULL,
  subject TEXT,
  raw_key TEXT NOT NULL,
  raw_size INTEGER NOT NULL DEFAULT 0,
  message_id TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (address) REFERENCES addresses(address) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_mails_address_created
ON mails(address, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_mails_message_id
ON mails(message_id);
