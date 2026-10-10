-- Reverses 000002: credentials are required again, so the columns return to
-- NOT NULL. Fails on rows that are still NULL — set hashed_password and salt
-- (or delete abandoned rows) before downgrading.
ALTER TABLE users ALTER COLUMN hashed_password SET NOT NULL;
ALTER TABLE users ALTER COLUMN salt SET NOT NULL;