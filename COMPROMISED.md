# Compromised credentials

Written by the ScreenShield responder when a credential was shown on a recorded screen. The old value is burned: revoke it at the provider. The new value is a placeholder in the same format; fill in the real one from your secret manager.

| when (UTC) | incident | rule | file:line | old (masked) | new (masked) | status |
|---|---|---|---|---|---|---|
| 2026-10-10 00:39:58 | SS-20261010003958 | env-secret | demo/fake-secrets/payments.py:12 | `SMTP************26!"` | `SMTP************3958` | rotated in repo, revoke at provider, seen in room-live |
| 2026-10-10 00:39:58 | SS-20261010003958 | env-secret | demo/fake-secrets/.env.demo:4 | `AWS_************EKEY` | `AWS_************3958` | rotated in repo, revoke at provider, seen in room-live |
| 2026-10-10 00:39:58 | SS-20261010003958 | env-secret | demo/fake-secrets/.env.demo:7 | `SMTP************026!` | `SMTP************3958` | rotated in repo, revoke at provider, seen in room-live |
| 2026-10-10 00:39:58 | SS-20261010003958 | env-secret | demo/fake-secrets/.env.demo:8 | `INTE************3c4d` | `INTE************3958` | rotated in repo, revoke at provider, seen in room-live |
| 2026-10-10 00:39:58 | SS-20261010003958 | env-secret | demo/fake-secrets/.env.demo:9 | `ADMI************024!` | `ADMI************3958` | rotated in repo, revoke at provider, seen in room-live |
