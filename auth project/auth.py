"""
auth.py — A teaching-oriented authentication engine.

Built for a cybersecurity course. Every security decision is commented with the
*reason* behind it, because in this field the reasoning matters as much as the code.

Threats this engine is designed to resist, and how:
  - Password database theft .......... Argon2id slow hashing + per-password salt
  - Brute-force / credential stuffing  Account lockout with exponential backoff
  - Timing attacks on login .......... Constant-time verify + dummy hash for unknown users
  - Session hijacking via DB leak ..... Only SHA-256 *hashes* of session tokens are stored
  - Weak passwords ................... Enforced password policy
  - Phishing / stolen passwords ....... Optional TOTP multi-factor authentication

This uses a JSON file as a "database" for clarity. A real system would use a
proper DB, but every security control here transfers directly.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import tempfile
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHash


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

# Argon2id is the current (OWASP-recommended) password-hashing algorithm.
# These parameters trade CPU/RAM cost against login latency. Higher = harder
# for an attacker who steals the hash database to crack it offline.
PASSWORD_HASHER = PasswordHasher(
    time_cost=3,        # number of iterations
    memory_cost=65536,  # 64 MiB of memory per hash — defeats cheap GPU cracking
    parallelism=4,
)

MAX_FAILED_ATTEMPTS = 5          # failures before the account locks
BASE_LOCKOUT_SECONDS = 30        # first lockout duration; doubles each further trip
SESSION_LIFETIME = timedelta(hours=1)

MIN_PASSWORD_LENGTH = 12         # length beats complexity rules (NIST SP 800-63B)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _now() -> datetime:
    """Always work in timezone-aware UTC to avoid off-by-an-hour security bugs."""
    return datetime.now(timezone.utc)


def _hash_token(token: str) -> str:
    """
    Session tokens are 256-bit random values, so they are *high entropy*.
    Unlike passwords, they don't need a slow KDF — a fast SHA-256 is correct here.
    We store only the hash so a database leak cannot be replayed as a live session.
    """
    return hashlib.sha256(token.encode()).hexdigest()


class PasswordPolicyError(ValueError):
    """Raised when a chosen password fails the strength policy."""


def check_password_policy(password: str) -> None:
    """Enforce a minimal, modern password policy. Raises PasswordPolicyError."""
    problems = []
    if len(password) < MIN_PASSWORD_LENGTH:
        problems.append(f"at least {MIN_PASSWORD_LENGTH} characters")
    if not re.search(r"[A-Za-z]", password):
        problems.append("at least one letter")
    if not re.search(r"\d", password):
        problems.append("at least one digit")
    # A tiny stand-in for a real breached-password check (e.g. HaveIBeenPwned k-anonymity API).
    common = {"password", "123456", "qwerty", "letmein", "admin"}
    if password.lower() in common or password.lower().replace(" ", "") in common:
        problems.append("not be a commonly used password")
    if problems:
        raise PasswordPolicyError("Password must: " + ", ".join(problems) + ".")


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #

@dataclass
class User:
    username: str
    password_hash: str                  # Argon2id hash (salt is embedded in the string)
    totp_secret: Optional[str] = None   # set once the user enables MFA
    failed_attempts: int = 0
    lockouts: int = 0                   # how many times this account has been locked
    locked_until: Optional[str] = None  # ISO timestamp, or None

    def is_locked(self) -> bool:
        if self.locked_until is None:
            return False
        return _now() < datetime.fromisoformat(self.locked_until)

    @property
    def mfa_enabled(self) -> bool:
        return self.totp_secret is not None


@dataclass
class Session:
    token_hash: str          # we store the hash, never the raw token
    username: str
    expires_at: str          # ISO timestamp

    def is_valid(self) -> bool:
        return _now() < datetime.fromisoformat(self.expires_at)


# --------------------------------------------------------------------------- #
# Authentication service
# --------------------------------------------------------------------------- #

class AuthError(Exception):
    """Generic auth failure. The *message* is deliberately vague on the login
    path so we never reveal whether it was the username or password that was wrong."""


class AuthService:
    def __init__(self, db_path: str | Path = "users.json"):
        self.db_path = Path(db_path)
        self.users: dict[str, User] = {}
        self.sessions: dict[str, Session] = {}  # keyed by token_hash
        self._load()

    # ---- persistence ----------------------------------------------------- #

    def _load(self) -> None:
        if not self.db_path.exists():
            return
        data = json.loads(self.db_path.read_text())
        self.users = {u["username"]: User(**u) for u in data.get("users", [])}

    def _save(self) -> None:
        """Atomic write with restrictive permissions so the hash DB isn't world-readable."""
        payload = {"users": [asdict(u) for u in self.users.values()]}
        fd, tmp = tempfile.mkstemp(dir=self.db_path.parent or ".")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(payload, f, indent=2)
            os.chmod(tmp, 0o600)          # owner read/write only
            os.replace(tmp, self.db_path)  # atomic — no half-written file on crash
        except Exception:
            os.unlink(tmp)
            raise

    # ---- registration ---------------------------------------------------- #

    def register(self, username: str, password: str) -> None:
        username = username.strip().lower()
        if not username:
            raise AuthError("Username is required.")
        if username in self.users:
            # Note: in a public signup form, leaking "username taken" is a known
            # trade-off (usability vs. account enumeration). Be aware of it.
            raise AuthError("That username is already taken.")
        check_password_policy(password)

        # hash() generates a fresh random salt internally and embeds it in the output.
        self.users[username] = User(
            username=username,
            password_hash=PASSWORD_HASHER.hash(password),
        )
        self._save()

    # ---- login ----------------------------------------------------------- #

    def authenticate(self, username: str, password: str, totp_code: Optional[str] = None) -> str:
        """
        Returns a session token on success. Raises AuthError otherwise.
        The error messages on the failure paths are intentionally identical/vague.
        """
        username = username.strip().lower()
        user = self.users.get(username)

        # Timing-attack defence: if the user doesn't exist, still perform a hash
        # verification against a dummy so the response time is the same whether or
        # not the username is valid. This prevents username enumeration by timing.
        if user is None:
            try:
                PASSWORD_HASHER.verify(
                    "$argon2id$v=19$m=65536,t=3,p=4$"
                    "c29tZXNhbHRzb21lc2FsdA$"
                    "RdescudvJCsgt3ub+b+dWRWJTmaaJObG",
                    password,
                )
            except Exception:
                pass
            raise AuthError("Invalid username or password.")

        if user.is_locked():
            remaining = datetime.fromisoformat(user.locked_until) - _now()
            raise AuthError(f"Account locked. Try again in {int(remaining.total_seconds())}s.")

        # verify() runs in constant time and raises if the password is wrong.
        try:
            PASSWORD_HASHER.verify(user.password_hash, password)
        except (VerifyMismatchError, VerificationError, InvalidHash):
            self._register_failure(user)
            raise AuthError("Invalid username or password.")

        # Password correct. If the stored hash used weaker params than our current
        # config (e.g. we raised the cost later), transparently upgrade it.
        if PASSWORD_HASHER.check_needs_rehash(user.password_hash):
            user.password_hash = PASSWORD_HASHER.hash(password)

        # Second factor, if the user has enrolled.
        if user.mfa_enabled:
            if not totp_code:
                raise AuthError("MFA code required.")
            totp = pyotp.TOTP(user.totp_secret)
            # valid_window=1 tolerates clock drift of one 30s step either side.
            if not totp.verify(totp_code, valid_window=1):
                self._register_failure(user)
                raise AuthError("Invalid MFA code.")

        # Success — clear the failure counter and issue a session.
        user.failed_attempts = 0
        user.locked_until = None
        self._save()
        return self._create_session(username)

    def _register_failure(self, user: User) -> None:
        user.failed_attempts += 1
        if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
            user.lockouts += 1
            # Exponential backoff: each lockout lasts twice as long as the last.
            duration = BASE_LOCKOUT_SECONDS * (2 ** (user.lockouts - 1))
            user.locked_until = (_now() + timedelta(seconds=duration)).isoformat()
            user.failed_attempts = 0
        self._save()

    # ---- MFA -------------------------------------------------------------- #

    def enable_mfa(self, username: str) -> str:
        """
        Generates a TOTP secret and returns an otpauth:// URI. The user scans this
        into an authenticator app (Google Authenticator, Aegis, etc.).
        """
        user = self.users[username.strip().lower()]
        secret = pyotp.random_base32()
        user.totp_secret = secret
        self._save()
        return pyotp.TOTP(secret).provisioning_uri(name=user.username, issuer_name="DemoAuth")

    # ---- sessions --------------------------------------------------------- #

    def _create_session(self, username: str) -> str:
        token = secrets.token_urlsafe(32)  # 256 bits of CSPRNG entropy
        token_hash = _hash_token(token)
        self.sessions[token_hash] = Session(
            token_hash=token_hash,
            username=username,
            expires_at=(_now() + SESSION_LIFETIME).isoformat(),
        )
        return token  # the raw token goes to the client; we keep only its hash

    def whoami(self, token: str) -> Optional[str]:
        session = self.sessions.get(_hash_token(token))
        if session is None or not session.is_valid():
            return None
        return session.username

    def logout(self, token: str) -> None:
        self.sessions.pop(_hash_token(token), None)
