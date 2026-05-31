-- JWT revocation: each issued token carries the user's current `token_version`.
-- Bumping this column (e.g. on password change or explicit "log out everywhere")
-- invalidates every token already in the wild, since the AuthUser extractor
-- compares the claim against the live DB value on every request.
ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 1;
