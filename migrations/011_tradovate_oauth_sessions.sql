ALTER TABLE tradovate_oauth_states
ADD COLUMN oauth_session_hash TEXT;

ALTER TABLE tradovate_oauth_states
ADD COLUMN oauth_session_last8 TEXT;

ALTER TABLE tradovate_oauth_states
ADD COLUMN oauth_session_encrypted TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_tradovate_oauth_session_hash
ON tradovate_oauth_states(oauth_session_hash)
WHERE oauth_session_hash IS NOT NULL;
