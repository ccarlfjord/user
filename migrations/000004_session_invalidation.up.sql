-- Sessions carry the account's session_epoch, and changing a password
-- increments it, which retires every session minted before the change so a
-- token that is already in the wrong hands stops working. A counter rather
-- than a timestamp keeps the check independent of clocks — the signing key is
-- shared through the database, so more than one instance may serve a request —
-- and of the one-second resolution of JWT date claims, which would otherwise
-- reject a session minted in the same second as the change.
ALTER TABLE users ADD COLUMN IF NOT EXISTS session_epoch INTEGER NOT NULL DEFAULT 0;
