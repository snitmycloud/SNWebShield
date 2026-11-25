# Test data cleanup log

## 2026-11-25 18:43 UTC: synthetic account `phase1-owner@example.com` (id 5, role user)

Removed:
- websites: four.phase1-proof.example.com, one.phase1-proof.example.com, six.phase1-proof.example.com, snitsolutions.in, three.phase1-proof.example.com, two.phase1-proof.example.com
- execution_events: 10
- websites: 6
- account_tokens: 2
- revoked_tokens: 0

Kept: the account row as an anonymized, disabled tombstone (email `deleted-user-5@deleted.invalid`, no name, random unknown password, cannot sign in) and its 5 `auth_events` rows, because that table is append-only (database triggers forbid update and delete) and the audit log must stay complete.

