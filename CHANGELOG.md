# Changelog

## Unreleased — authentication and authorisation correctness

- Normalise new permission windows to UTC and preserve original decision history separately from effective validity.
- Add Alembic baseline adoption and a provenance flag; preserve legacy dates and require their review instead of guessing timezone offsets.
- Enforce conditional decision transitions and transactional audit-event writes.
- Add whole-dataset authorisation summaries and computed website validity states.
- Fix idle/request-time session expiry, stale responses after logout, dashboard counts and status labels.
- Add isolated backend, migration, frontend helper and Windows browser regression suites, plus a verified SQLite backup command.
- Reconcile setup documentation. Browser acceptance and PostgreSQL verification remain pending.

## Unreleased — authorisation evidence

- Private UUID-addressed PDF/image uploads, content validation, SHA-256 verification and authenticated downloads/previews.
- Human evidence reviews tied to actor and revision; approval requires current accepted evidence.
- Evidence metadata/history, legal holds and retention-checked deletion with retryable tombstones.
- Additive migration 0003_evidence; existing data preserved.
- Local implementation prepared; updated Windows browser verification and PostgreSQL integration remain pending.
