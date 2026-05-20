# =============================================================================
# app/models.py
# Shared models — ALL THREE developers use this file.
# Developer 1 is the primary author of User and AuditLog.
# Developer 2 will append: Product, Category, Cart, CartItem
# Developer 3 will append: Order, OrderItem
#
# IMPORTANT: Never edit existing classes — only append new ones at the bottom.
# All schema changes go through: flask db migrate -m "description"
# =============================================================================

import uuid
from datetime import datetime, timezone

from flask_login import UserMixin
from app.extensions import db


# -----------------------------------------------------------------------------
# Helper
# -----------------------------------------------------------------------------

def _new_uuid() -> str:
    """Generate a UUID4 string for use as a primary key."""
    return str(uuid.uuid4())


# -----------------------------------------------------------------------------
# User
# -----------------------------------------------------------------------------

class User(UserMixin, db.Model):
    """
    Represents a registered user, synced from Auth0 after first login.

    Auth0 owns the identity (password, MFA, social login).
    This table owns the application data (role, cart, orders, audit trail).

    STRIDE mitigations:
      Spoofing          — identity verified by Auth0 JWT before this row is
                          created or queried. We never store passwords.
      Tampering         — role is set server-side only; never from request body.
      Repudiation       — every auth event written to AuditLog.
      Info Disclosure   — to_dict() whitelists safe fields only.
      Elevation         — role field defaults to 'customer'; only admin code
                          can set 'admin'. Enforced by require_role decorator.
    """

    __tablename__ = "users"

    # ------------------------------------------------------------------
    # Primary key
    # ------------------------------------------------------------------
    id = db.Column(db.String(36), primary_key=True, default=_new_uuid)

    # ------------------------------------------------------------------
    # Auth0 identity link
    # auth0_id is the unique identifier Auth0 sends in every JWT ("sub" claim).
    # Format: "auth0|64f3c2..." or "google-oauth2|117..." for social logins.
    # This is the ONLY field that connects our DB row to Auth0.
    # ------------------------------------------------------------------
    auth0_id = db.Column(
        db.String(128), unique=True, nullable=False, index=True
    )

    # ------------------------------------------------------------------
    # Profile — populated from Auth0 token on first sync
    # ------------------------------------------------------------------
    email = db.Column(db.String(254), unique=True, nullable=False, index=True)
    username = db.Column(db.String(50), nullable=False)

    # is_verified mirrors Auth0's email_verified claim.
    # Updated on every sync so it stays in step with Auth0.
    # STRIDE Info Disclosure: unverified users blocked from sensitive routes
    # via the @verified_required decorator.
    is_verified = db.Column(db.Boolean, nullable=False, default=False)

    # ------------------------------------------------------------------
    # Role-based access control
    # STRIDE Elevation of Privilege: role is NEVER taken from the request.
    # Allowed values: 'customer' | 'admin'
    # ------------------------------------------------------------------
    role = db.Column(db.String(20), nullable=False, default="customer")

    # ------------------------------------------------------------------
    # Account state
    # ------------------------------------------------------------------
    is_active = db.Column(db.Boolean, nullable=False, default=True)

    # ------------------------------------------------------------------
    # Timestamps
    # ------------------------------------------------------------------
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    last_login_at = db.Column(db.DateTime(timezone=True), nullable=True)

    # ------------------------------------------------------------------
    # Relationships
    # ------------------------------------------------------------------
    audit_logs = db.relationship(
        "AuditLog",
        back_populates="user",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )
    # Developer 2 will add: carts, and products (if needed)
    # Developer 3 will add: orders

    # ------------------------------------------------------------------
    # Flask-Login required method
    # ------------------------------------------------------------------
    def get_id(self) -> str:
        return self.id

    # ------------------------------------------------------------------
    # Serialisation
    # STRIDE Info Disclosure: only safe fields are returned.
    # auth0_id is intentionally excluded from API responses.
    # ------------------------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "id":            self.id,
            "email":         self.email,
            "username":      self.username,
            "role":          self.role,
            "is_verified":   self.is_verified,
            "is_active":     self.is_active,
            "created_at":    self.created_at.isoformat(),
            "last_login_at": self.last_login_at.isoformat()
                             if self.last_login_at else None,
        }

    def __repr__(self) -> str:
        return f"<User {self.email} role={self.role}>"


# -----------------------------------------------------------------------------
# AuditLog
# -----------------------------------------------------------------------------

class AuditLog(db.Model):
    """
    Immutable, append-only log of security-relevant events.

    STRIDE Repudiation: provides a tamper-evident trail for every
    significant action — login, logout, sync, role change, order, payment.

    Rules:
      - Never UPDATE or DELETE rows in this table.
      - Always call AuditLog.record() then db.session.commit() together.
      - Keep detail strings short; never log passwords, tokens, or card data.

    Used by all three developers:
      Dev 1 — LOGIN_AUTH0, LOGOUT, SYNC_USER, ROLE_CHANGE
      Dev 2 — CART_ADD, CART_REMOVE, CART_CLEAR
      Dev 3 — CHECKOUT_INITIATED, PAYMENT_CONFIRMED, PAYMENT_FAILED
    """

    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    # Nullable so we can log events before a user row exists (e.g. unknown token)
    user_id = db.Column(
        db.String(36),
        db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Short uppercase event name  e.g. 'LOGIN_AUTH0', 'PAYMENT_CONFIRMED'
    event = db.Column(db.String(64), nullable=False, index=True)

    # Network info — stored for incident investigation
    # STRIDE Info Disclosure: IP stored for security purposes only;
    # never returned in public API responses.
    ip_address = db.Column(db.String(45), nullable=True)   # supports IPv6
    user_agent = db.Column(db.String(256), nullable=True)

    # Optional short detail string — e.g. order ID, last 4 card digits
    # NEVER store passwords, full card numbers, or Auth0 tokens here.
    detail = db.Column(db.String(512), nullable=True)

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    user = db.relationship("User", back_populates="audit_logs")

    # ------------------------------------------------------------------
    # Factory method — use this everywhere instead of direct instantiation
    # ------------------------------------------------------------------
    @classmethod
    def record(
        cls,
        event: str,
        user_id:    str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        detail:     str | None = None,
    ) -> "AuditLog":
        """
        Create an AuditLog entry and add it to the session.
        Caller is responsible for calling db.session.commit().

        Example:
            AuditLog.record(
                event="LOGIN_AUTH0",
                user_id=user.id,
                ip_address=request.remote_addr,
                detail="Auth0 sub: auth0|64f3c2..."
            )
            db.session.commit()
        """
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
        return (
            f"<AuditLog event={self.event} "
            f"user={self.user_id} at={self.created_at}>"
        )


# =============================================================================
# Developer 2 appends Product, Category, Cart, CartItem below this line.
# Developer 3 appends Order, OrderItem below Developer 2's models.
# =============================================================================
