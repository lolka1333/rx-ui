-- One subscription URL per client, not one per attachment.
--
-- `sub_token` was minted per row — per (client, inbound) pair — while the URL
-- it builds is per client: `/sub/{token}` resolves to the row's email and
-- serves every attachment of that email. So a client in three inbounds had
-- three URLs, and the panel showed whichever row the list returned first, the
-- newest. Adding an inbound changed the URL on screen; removing the inbound
-- whose row had minted the URL a user was given turned that URL into a 404;
-- and resetting the link replaced one of the three while the other two went
-- on working.
--
-- From here the token is shared by every row of an email, the way its uuid
-- is: a new attachment inherits it, removing one leaves it alone, and a reset
-- replaces it on all of them at once. The UNIQUE index goes, since the column
-- now repeats by design; a plain one keeps the public lookup O(log n).
--
-- Every URL already handed out keeps working. Each email is unified on the
-- token of its oldest row, and its other tokens — any of which may be in a
-- user's app, because the panel used to show the newest row's — are kept in
-- `sub_token_aliases`, which the subscription endpoint falls back to.

DROP INDEX idx_clients_sub_token;
CREATE INDEX idx_clients_sub_token ON clients (sub_token);

CREATE TABLE sub_token_aliases (
    token      TEXT PRIMARY KEY NOT NULL,
    email      TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_sub_token_aliases_email ON sub_token_aliases (email);

-- The token an email keeps: its oldest row's. `''` is the column default from
-- migration 0022, never a token, so it neither wins nor becomes an alias. The
-- aliases are taken BEFORE the rows are rewritten, while they still hold them.
INSERT OR IGNORE INTO sub_token_aliases (token, email)
SELECT c.sub_token, c.email
FROM clients c
WHERE c.sub_token <> ''
  AND c.sub_token <> (
      SELECT o.sub_token FROM clients o
      WHERE o.email = c.email AND o.sub_token <> ''
      ORDER BY o.created_at ASC, o.id ASC
      LIMIT 1
  );

-- COALESCE keeps a row as it is when its email has no token at all — there is
-- nothing better to give it, and NULL would break the NOT NULL column.
UPDATE clients SET sub_token = COALESCE(
    (
        SELECT o.sub_token FROM clients o
        WHERE o.email = clients.email AND o.sub_token <> ''
        ORDER BY o.created_at ASC, o.id ASC
        LIMIT 1
    ),
    sub_token
);

-- An alias lives exactly as long as its email has a row. Without this, a
-- client deleted and later created again under the same email would get the
-- old client's URLs back. A trigger rather than application code, because rows
-- also go by cascade when their inbound is deleted, and SQLite fires row
-- triggers for those deletes too.
CREATE TRIGGER sub_token_aliases_die_with_email
AFTER DELETE ON clients
WHEN NOT EXISTS (SELECT 1 FROM clients WHERE email = OLD.email)
BEGIN
    DELETE FROM sub_token_aliases WHERE email = OLD.email;
END;
