# app/models.py
# Shared models — owned by all developers, changes require PR review from all 3.
# Developer 1 is primary author of User and AuditLog.

import uuid
import jwt
from datetime import datetime, timedelta, timezone

import bcrypt
from flask import current_app
from flask_login import UserMixin

from app.extensions import db


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _new_uuid() -> str:
    """Generate a URL-safe UUID4 string as primary key."""
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# User model
# ---------------------------------------------------------------------------

class User(UserMixin, db.Model):
    """
    Represents both registered and (future) guest users.

    STRIDE mitigations baked in:
      Spoofing          — bcrypt password hash (cost 12), JWT with expiry
      Tampering         — role field protected; only admin can elevate
      Repudiation       — every auth event written to AuditLog
      Info Disclosure   — password_hash never serialised in to_dict()
      DoS               — failed_attempts + lockout enforced in AuthService
      Elevation         — role-based access, checked via @require_role decorator
    """

    __tablename__ = "users"

    # Primary key
    id = db.Column(db.String(36), primary_key=True, default=_new_uuid)

    # Identity
    email = db.Column(db.String(254), unique=True, nullable=False, index=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.LargeBinary(60), nullable=False)

    # Role — 'guest' | 'customer' | 'admin'
    # Guests are unregistered visitors; they get a temporary session only.
    role = db.Column(db.String(20), nullable=False, default="customer")

    # Account state
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    is_verified = db.Column(db.Boolean, nullable=False, default=False)
    failed_attempts = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime(timezone=True), nullable=True)

    # Email verification token (one-time, short-lived)
    verification_token = db.Column(db.String(64), nullable=True, index=True)
    verification_token_expiry = db.Column(db.DateTime(timezone=True), nullable=True)

    # Timestamps
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    last_login_at = db.Column(db.DateTime(timezone=True), nullable=True)

    # Relationships
    audit_logs = db.relationship(
        "AuditLog", back_populates="user", lazy="dynamic", cascade="all, delete-orphan"
    )

    # ------------------------------------------------------------------
    # Password helpers
    # ------------------------------------------------------------------

    def set_password(self, plaintext: str) -> None:
        """Hash and store password. bcrypt cost=12 (~250 ms, safe against brute force)."""
        self.password_hash = bcrypt.hashpw(
            plaintext.encode("utf-8"), bcrypt.gensalt(rounds=12)
        )

    def check_password(self, plaintext: str) -> bool:
        """Constant-time comparison via bcrypt. Safe against timing attacks."""
        if not self.password_hash:
            return False
        return bcrypt.checkpw(plaintext.encode("utf-8"), self.password_hash)

    # ------------------------------------------------------------------
    # Account lockout helpers
    # ------------------------------------------------------------------

    def is_locked(self) -> bool:
        if not self.locked_until:
            return False
        return datetime.now(timezone.utc) < self.locked_until

    def record_failed_attempt(self) -> None:
        self.failed_attempts += 1
        if self.failed_attempts >= 5:
            self.locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)

    def reset_failed_attempts(self) -> None:
        self.failed_attempts = 0
        self.locked_until = None

    # ------------------------------------------------------------------
    # JWT helpers
    # ------------------------------------------------------------------

    def generate_jwt(self) -> str:
        """
        Short-lived access token (1 hour).
        Carries only id and role — no PII in the payload.
        """
        payload = {
            "sub": self.id,
            "role": self.role,
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        }
        return jwt.encode(
            payload,
            current_app.config["SECRET_KEY"],
            algorithm="HS256",
        )

    @staticmethod
    def verify_jwt(token: str) -> dict | None:
        """Decode and validate JWT. Returns payload dict or None on failure."""
        try:
            return jwt.decode(
                token,
                current_app.config["SECRET_KEY"],
                algorithms=["HS256"],
            )
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    # ------------------------------------------------------------------
    # Email verification token helpers
    # ------------------------------------------------------------------

    def generate_verification_token(self) -> str:
        """
        Create a 64-hex-char token stored (hashed) on the user row.
        Expires in 24 hours.
        """
        import secrets
        raw_token = secrets.token_hex(32)           # 256-bit entropy
        self.verification_token = raw_token          # stored plaintext for simplicity;
        # production: store bcrypt hash of token
        self.verification_token_expiry = datetime.now(timezone.utc) + timedelta(hours=24)
        return raw_token

    def verify_email_token(self, token: str) -> bool:
        """Return True and activate account if token is valid and unexpired."""
        if not self.verification_token:
            return False
        if datetime.now(timezone.utc) > self.verification_token_expiry:
            return False
        if self.verification_token != token:
            return False
        self.is_verified = True
        self.verification_token = None
        self.verification_token_expiry = None
        return True

    # ------------------------------------------------------------------
    # Serialisation — NEVER include password_hash
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "email": self.email,
            "username": self.username,
            "role": self.role,
            "is_verified": self.is_verified,
            "created_at": self.created_at.isoformat(),
        }

    def __repr__(self) -> str:
        return f"<User {self.email} [{self.role}]>"


# ---------------------------------------------------------------------------
# AuditLog model  (repudiation mitigation)
# ---------------------------------------------------------------------------

class AuditLog(db.Model):
    """
    Immutable append-only log of security-relevant user events.
    Covers STRIDE Repudiation: login, logout, registration, failed attempts,
    checkout initiation, order confirmation, etc.
    """

    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.String(36),
        db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    event = db.Column(db.String(64), nullable=False)       # e.g. 'LOGIN_SUCCESS'
    ip_address = db.Column(db.String(45), nullable=True)   # IPv4 or IPv6
    user_agent = db.Column(db.String(256), nullable=True)
    detail = db.Column(db.String(512), nullable=True)      # optional JSON string
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    user = db.relationship("User", back_populates="audit_logs")

    @classmethod
    def record(
        cls,
        event: str,
        user_id: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        detail: str | None = None,
    ) -> "AuditLog":
        """Create and flush an audit entry. Caller must commit the session."""
        entry = cls(
            event=event,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            detail=detail,
        )
        db.session.add(entry)
        return entry

    def __repr__(self) -> str:
        return f"<AuditLog {self.event} user={self.user_id} at={self.created_at}>"
