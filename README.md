# auth3000
Since authentication is foundational to security coursework, I made it demonstrate the practices that actually matter in the field . proper password hashing, brute-force protection, secure sessions, and MFA , with comments explaining the why behind each decision

# Secure Authentication Demo

A small but realistic authentication system written for a cybersecurity course.
The goal is to demonstrate the security controls that matter in real systems and,
just as importantly, the reasoning behind them.

## Run it

```bash
pip install argon2-cffi pyotp
python3 cli.py
```

Optional, for a scannable MFA QR code in the terminal: `pip install qrcode`.

## Files

- `auth.py` — the authentication engine (all security logic lives here)
- `cli.py` — a thin interactive terminal front-end
- `requirements.txt` — dependencies

## Threat model and controls

| Threat | Control in this code |
|---|---|
| Stolen password database | Passwords stored as **Argon2id** hashes with a per-password salt and high memory cost, making offline cracking expensive. |
| Brute-force / credential stuffing | **Account lockout** after 5 failed attempts, with **exponential backoff** (each lockout lasts twice as long). |
| Username enumeration by timing | On an unknown username, a **dummy hash verification** still runs so the response time matches a real account; error messages are identical. |
| Session token theft via DB leak | Only the **SHA-256 hash** of each session token is stored, never the raw token. A leaked store cannot be replayed. |
| Weak passwords | Enforced **password policy** (length-first, per NIST SP 800-63B) plus a small common-password blocklist. |
| Stolen/phished passwords | Optional **TOTP multi-factor authentication** (RFC 6238). |
| Half-written DB on crash | **Atomic writes** (temp file + `os.replace`) with `0600` file permissions. |

## Things to note (good exam talking points)

- **Why a slow hash for passwords but a fast hash for tokens?** Passwords are
  low-entropy, so we deliberately make each guess expensive (Argon2id). Session
  tokens are 256-bit random values, so a fast SHA-256 is appropriate — there's
  nothing to brute-force.
- **`check_needs_rehash`** transparently upgrades old hashes when you raise the
  cost parameters later, without forcing a password reset.
- The common-password check is a stand-in for a real **breached-password lookup**
  (e.g. the HaveIBeenPwned k-anonymity API), which you could add as an extension.

## Honest limitations

This is a teaching artifact, not production code. A real deployment would use a
proper database, run over TLS, set `HttpOnly`/`Secure`/`SameSite` cookies for
sessions, add CSRF protection, and integrate a real breached-password service.
