# Compromised credentials

Written by the ScreenShield responder when a credential was shown on a recorded screen. The old value is burned: revoke it at the provider. The new value is a placeholder in the same format; fill in the real one from your secret manager.

| when (UTC) | incident | rule | file:line | old (masked) | new (masked) | status |
|---|---|---|---|---|---|---|
| 2026-10-10 00:36:14 | SS-20261010003614 | aws-access-key | demo/fake-secrets/payments.py:11 | `AKIA************MPLE` | `AKIA************0100` | rotated in repo, revoke at provider, seen in room-live |
| 2026-10-10 00:36:14 | SS-20261010003614 | aws-access-key | demo/fake-secrets/.env.demo:3 | `AKIA************MPLE` | `AKIA************0100` | rotated in repo, revoke at provider, seen in room-live |
| 2026-10-10 00:36:14 | SS-20261010003614 | aws-access-key | demo/fake-secrets/README.md:4 | `AKIA************MPLE` | `AKIA************0100` | rotated in repo, revoke at provider, seen in room-live |
