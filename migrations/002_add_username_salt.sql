ALTER TABLE users ADD COLUMN username TEXT UNIQUE;
ALTER TABLE users ADD COLUMN salt BYTEA;
CREATE UNIQUE INDEX idx_users_username ON users(username);
