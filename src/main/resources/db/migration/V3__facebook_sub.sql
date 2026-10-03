-- Facebook sign-in: stable per-user Facebook id, used to match a Facebook
-- login to an existing account on subsequent sign-ins.
ALTER TABLE users ADD COLUMN facebook_sub VARCHAR(128);

-- Plain unique index rather than a partial one: every supported database
-- already lets a UNIQUE column hold more than one NULL, so the partial-index
-- filter would add nothing, and H2 (used by the test suite) rejects the
-- WHERE clause outright.
CREATE UNIQUE INDEX idx_users_facebook_sub ON users (facebook_sub);
