CREATE TABLE IF NOT EXISTS login_nonce (id TEXT PRIMARY KEY,binding TEXT NOT NULL,expires INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS login_nonce_expiry ON login_nonce(expires);
CREATE TABLE IF NOT EXISTS auth_rate (id TEXT PRIMARY KEY,n INTEGER NOT NULL,expires INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS auth_rate_expiry ON auth_rate(expires);
