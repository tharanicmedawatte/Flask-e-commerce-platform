# =============================================================================
# app/models.py
# Complete database models for the entire e-commerce platform.
#
# This is a SHARED file — owned and used by all three developers.
# It is the single source of truth for the database schema.
#
# RULES FOR ALL THREE DEVELOPERS:
#   - Never edit another developer's section without telling the team
#   - All schema changes go through flask db migrate — never edit DB directly
#   - Never delete or rename existing columns — it breaks other developers
#   - If you need a new column, add it at the bottom of that model
#   - Never store passwords, full card numbers, or raw tokens here
#
# TABLE OF CONTENTS:
#   Section 1 — Shared helpers
#   Section 2 — Developer 1: User, AuditLog
#   Section 3 — Developer 2: Category, Product, Cart, CartItem
#   Section 4 — Developer 3: Order, OrderItem
#
# DATABASE RELATIONSHIPS:
#   User ──────────── AuditLog      (one user → many log entries)
#   User ──────────── Cart          (one user → one cart)
#   User ──────────── Order         (one user → many orders)
#   Category ──────── Product       (one category → many products)
#   Cart ───────────── CartItem     (one cart → many items)
#   CartItem ───────── Product      (each cart item → one product)
#   Order ──────────── OrderItem    (one order → many items)
#   OrderItem ──────── Product      (each order item → one product)
#
# STRIDE coverage:
#   Spoofing        — User.auth0_id links identity to verified Auth0 token
#   Tampering       — prices always read from Product.price server-side;
#                     CartItem stores NO price; OrderItem stores snapshot
#   Repudiation     — AuditLog records every significant event immutably
#   Info Disclosure — to_dict() methods whitelist safe fields only;
#                     cost_price never returned in public responses
#   Elevation       — User.role server-side only, defaults to 'customer'
# =============================================================================

import uuid
from datetime import datetime, timezone
from decimal import Decimal

from flask_login import UserMixin
from sqlalchemy import Numeric

from app.extensions import db


# =============================================================================
# SECTION 1 — Shared helpers
# =============================================================================

def _new_uuid() -> str:
    """Generate a UUID4 string for use as a primary key."""
    return str(uuid.uuid4())


# =============================================================================
# SECTION 2 — Developer 1: User, AuditLog
# =============================================================================

class User(UserMixin, db.Model):
    """
    Represents a registered user, synced from Auth0 after first login.

    Auth0 owns the identity (password, MFA, social login).
    This table owns the application data (role, cart, orders, audit trail).

    STRIDE Spoofing:      auth0_id links our row to a verified Auth0 identity.
                          We never store passwords.
    STRIDE Tampering:     role is set server-side only, never from request body.
    STRIDE Repudiation:   every auth event written to AuditLog.
    STRIDE Info Disc.:    to_dict() whitelists safe fields only.
    STRIDE Elevation:     role defaults to 'customer', never from client input.
    """

    __tablename__ = "users"

    # ------------------------------------------------------------------
    # Primary key
    # ------------------------------------------------------------------
    id = db.Column(db.String(36), primary_key=True, default=_new_uuid)

    # ------------------------------------------------------------------
    # Auth0 identity
    # The "sub" claim from every Auth0 JWT.
    # Format: "auth0|64f3c2..." or "google-oauth2|117..." for social login.
    # ------------------------------------------------------------------
    auth0_id = db.Column(
        db.String(128), unique=True, nullable=False, index=True
    )

    # ------------------------------------------------------------------
    # Profile — populated from Auth0 token on first sync
    # ------------------------------------------------------------------
    email    = db.Column(db.String(254), unique=True, nullable=False, index=True)
    username = db.Column(db.String(50),  nullable=False)

    # Mirrors Auth0's email_verified claim — updated on every /auth/sync
    is_verified = db.Column(db.Boolean, nullable=False, default=False)

    # ------------------------------------------------------------------
    # Role-based access control
    # STRIDE Elevation: role is NEVER taken from the request or JWT payload.
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
    cart = db.relationship(
        "Cart",
        back_populates="user",
        uselist=False,              # one user → one cart (not a list)
        cascade="all, delete-orphan",
    )
    orders = db.relationship(
        "Order",
        back_populates="user",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )

    # ------------------------------------------------------------------
    # Flask-Login
    # ------------------------------------------------------------------
    def get_id(self) -> str:
        return self.id

    # ------------------------------------------------------------------
    # Serialisation
    # STRIDE Info Disclosure: auth0_id intentionally excluded.
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

class AuditLog(db.Model):
    """
    Immutable, append-only log of security-relevant events.

    STRIDE Repudiation: every significant action is recorded here.
    Rules:
      - Never UPDATE or DELETE rows in this table.
      - Call AuditLog.record() then db.session.commit() together.
      - Never log passwords, tokens, or full card numbers in detail field.

    Events by developer:
      Dev 1 — LOGIN_AUTH0, LOGOUT, SYNC_USER, ACCESS_DENIED_*
      Dev 2 — CART_ADD, CART_REMOVE, CART_CLEAR, CART_UPDATE
      Dev 3 — CHECKOUT_INITIATED, PAYMENT_CONFIRMED, PAYMENT_FAILED,
              WEBHOOK_RECEIVED
    """

    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    # Nullable — allows logging events before a user row exists
    user_id = db.Column(
        db.String(36),
        db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Short uppercase event name e.g. 'LOGIN_AUTH0', 'PAYMENT_CONFIRMED'
    event = db.Column(db.String(64), nullable=False, index=True)

    # Network info — stored for security investigation only
    # STRIDE Info Disclosure: never returned in public API responses
    ip_address = db.Column(db.String(45),  nullable=True)   # supports IPv6
    user_agent = db.Column(db.String(256), nullable=True)

    # Optional short context — e.g. order ID, last 4 card digits
    # NEVER store passwords, full card numbers, or tokens here
    detail = db.Column(db.String(512), nullable=True)

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    user = db.relationship("User", back_populates="audit_logs")

    @classmethod
    def record(
        cls,
        event:      str,
        user_id:    str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        detail:     str | None = None,
    ) -> "AuditLog":
        """
        Create and stage an AuditLog entry.
        Caller must call db.session.commit() to persist it.

        Example:
            AuditLog.record(
                event="LOGIN_AUTH0",
                user_id=user.id,
                ip_address=request.remote_addr,
                detail="first login"
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
        return f"<AuditLog {self.event} user={self.user_id} at={self.created_at}>"


# =============================================================================
# SECTION 3 — Developer 2: Category, Product, Cart, CartItem
# =============================================================================

class Category(db.Model):
    """
    Product category e.g. "Electronics", "Clothing", "Books".
    Simple flat list — can be made hierarchical later by adding
    a parent_id self-referential foreign key if needed.
    """

    __tablename__ = "categories"

    id          = db.Column(db.Integer,     primary_key=True, autoincrement=True)
    name        = db.Column(db.String(100), unique=True, nullable=False)
    slug        = db.Column(db.String(100), unique=True, nullable=False, index=True)
    # slug is the URL-safe version: "electronics", "mens-clothing"
    # Used in URLs: /products?category=mens-clothing

    description = db.Column(db.String(500), nullable=True)
    is_active   = db.Column(db.Boolean,     nullable=False, default=True)
    created_at  = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Relationship
    products = db.relationship(
        "Product",
        back_populates="category",
        lazy="dynamic",
    )

    def to_dict(self) -> dict:
        return {
            "id":          self.id,
            "name":        self.name,
            "slug":        self.slug,
            "description": self.description,
        }

    def __repr__(self) -> str:
        return f"<Category {self.name}>"


# -----------------------------------------------------------------------------

class Product(db.Model):
    """
    A product available for purchase.

    STRIDE Tampering:
        price is the authoritative value — always read from this table.
        Never from the frontend, cart, or order request body.
        CartItem stores NO price.
        OrderItem stores price_at_purchase as a point-in-time snapshot
        taken from this table at checkout.

    STRIDE Info Disclosure:
        cost_price (wholesale cost) is stored here but excluded from
        all public API responses. to_dict() never includes it.
    """

    __tablename__ = "products"

    id          = db.Column(db.String(36),  primary_key=True, default=_new_uuid)
    category_id = db.Column(
        db.Integer,
        db.ForeignKey("categories.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # ------------------------------------------------------------------
    # Product details
    # ------------------------------------------------------------------
    name        = db.Column(db.String(200), nullable=False)
    slug        = db.Column(db.String(200), unique=True, nullable=False, index=True)
    description = db.Column(db.Text,        nullable=True)
    sku         = db.Column(db.String(100), unique=True, nullable=True)
    image_url   = db.Column(db.String(500), nullable=True)

    # ------------------------------------------------------------------
    # Pricing
    # STRIDE Tampering: price is the ONLY authoritative source of truth.
    # cost_price is internal only — never returned in public API responses.
    # ------------------------------------------------------------------
    price      = db.Column(Numeric(10, 2), nullable=False)
    cost_price = db.Column(Numeric(10, 2), nullable=True)   # internal only

    # ------------------------------------------------------------------
    # Inventory
    # ------------------------------------------------------------------
    stock     = db.Column(db.Integer, nullable=False, default=0)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    # is_active=False hides product from public listing without deleting it

    # ------------------------------------------------------------------
    # Timestamps
    # ------------------------------------------------------------------
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # ------------------------------------------------------------------
    # Relationships
    # ------------------------------------------------------------------
    category    = db.relationship("Category",  back_populates="products")
    cart_items  = db.relationship("CartItem",  back_populates="product")
    order_items = db.relationship("OrderItem", back_populates="product")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def is_in_stock(self, quantity: int = 1) -> bool:
        """Check if the requested quantity is available."""
        return self.is_active and self.stock >= quantity

    # ------------------------------------------------------------------
    # Serialisation
    # STRIDE Info Disclosure: cost_price excluded from public response.
    # ------------------------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "id":          self.id,
            "name":        self.name,
            "slug":        self.slug,
            "description": self.description,
            "sku":         self.sku,
            "image_url":   self.image_url,
            "price":       str(self.price),     # string avoids float precision issues
            "stock":       self.stock,
            "in_stock":    self.stock > 0,
            "category":    self.category.to_dict() if self.category else None,
            "created_at":  self.created_at.isoformat(),
        }
        # cost_price intentionally excluded

    def __repr__(self) -> str:
        return f"<Product {self.name} price={self.price} stock={self.stock}>"


# -----------------------------------------------------------------------------

class Cart(db.Model):
    """
    A shopping cart — one per registered user, persisted in the database.

    STRIDE Tampering:
        Cart stores only product_id and quantity — NEVER price.
        Total is always calculated at checkout by reading Product.price
        fresh from the database. A user cannot manipulate price by
        editing their cart request body.

    Guest carts:
        Unregistered users have a session-based cart in the Flask session
        cookie — no DB row is created until they register.
        When a guest registers, their session cart is merged into this table
        by CartService.merge_guest_cart().
    """

    __tablename__ = "carts"

    id      = db.Column(db.String(36), primary_key=True, default=_new_uuid)
    user_id = db.Column(
        db.String(36),
        db.ForeignKey("users.id", ondelete="CASCADE"),
        unique=True,        # one cart per user — enforced at DB level
        nullable=False,
        index=True,
    )
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    user  = db.relationship("User",     back_populates="cart")
    items = db.relationship(
        "CartItem",
        back_populates="cart",
        cascade="all, delete-orphan",
        lazy="joined",      # always load items with cart in one query
    )

    def calculate_total(self) -> Decimal:
        """
        Calculate cart total from live Product prices.
        STRIDE Tampering: price read from Product table, not from cart.
        """
        return sum(
            item.product.price * item.quantity
            for item in self.items
            if item.product and item.product.is_active
        )

    def to_dict(self) -> dict:
        return {
            "id":         self.id,
            "items":      [item.to_dict() for item in self.items],
            "total":      str(self.calculate_total()),
            "item_count": sum(item.quantity for item in self.items),
            "updated_at": self.updated_at.isoformat(),
        }

    def __repr__(self) -> str:
        return f"<Cart user={self.user_id} items={len(self.items)}>"


# -----------------------------------------------------------------------------

class CartItem(db.Model):
    """
    A single product line in a cart.

    Stores product_id and quantity ONLY — NO price field.
    Price is always read live from Product.price at checkout time.

    STRIDE Tampering:
        No price field means price manipulation via cart editing
        is architecturally impossible.
    """

    __tablename__ = "cart_items"

    id         = db.Column(db.Integer,    primary_key=True, autoincrement=True)
    cart_id    = db.Column(
        db.String(36),
        db.ForeignKey("carts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    product_id = db.Column(
        db.String(36),
        db.ForeignKey("products.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Must always be >= 1 — enforced in CartService, not just here
    quantity = db.Column(db.Integer, nullable=False, default=1)

    added_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # One row per product per cart — prevents duplicates
    # CartService increments quantity instead of inserting a new row
    __table_args__ = (
        db.UniqueConstraint("cart_id", "product_id", name="uq_cart_product"),
    )

    # Relationships
    cart    = db.relationship("Cart",    back_populates="items")
    product = db.relationship("Product", back_populates="cart_items")

    def to_dict(self) -> dict:
        return {
            "id":       self.id,
            "product":  self.product.to_dict() if self.product else None,
            "quantity": self.quantity,
            "subtotal": str(self.product.price * self.quantity)
                        if self.product else "0.00",
            "added_at": self.added_at.isoformat(),
        }

    def __repr__(self) -> str:
        return f"<CartItem product={self.product_id} qty={self.quantity}>"


# =============================================================================
# SECTION 4 — Developer 3: Order, OrderItem
# =============================================================================

class Order(db.Model):
    """
    A confirmed purchase — created when the user initiates checkout.

    STRIDE Tampering:
        total is calculated server-side from Product.price at checkout.
        It is the authoritative amount passed to Stripe — the frontend
        never sets it. Immutable after creation.

    STRIDE Repudiation:
        stripe_payment_intent_id links this order to Stripe's records
        for dispute resolution and reconciliation.
        Every status change is written to AuditLog by CheckoutService.

    Order lifecycle:
        pending   — checkout initiated, Stripe PaymentIntent created
        paid      — Stripe webhook confirmed payment succeeded
        failed    — Stripe webhook reported payment failure
        shipped   — admin marks as shipped
        delivered — admin marks as delivered
        refunded  — admin processed a refund via Stripe
        cancelled — cancelled before payment or after refund
    """

    __tablename__ = "orders"

    id      = db.Column(db.String(36), primary_key=True, default=_new_uuid)
    user_id = db.Column(
        db.String(36),
        db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,      # SET NULL preserves order history if user deleted
        index=True,
    )

    # ------------------------------------------------------------------
    # Financial
    # STRIDE Tampering: set at checkout from DB prices, never updated.
    # ------------------------------------------------------------------
    total    = db.Column(Numeric(10, 2), nullable=False)
    currency = db.Column(db.String(3),   nullable=False, default="USD")

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------
    status = db.Column(
        db.String(20),
        nullable=False,
        default="pending",
        index=True,
    )

    # ------------------------------------------------------------------
    # Stripe references
    # STRIDE Repudiation: links our records to Stripe for audit/dispute.
    # ------------------------------------------------------------------
    stripe_payment_intent_id = db.Column(db.String(128), nullable=True, index=True)
    stripe_charge_id         = db.Column(db.String(128), nullable=True)

    # ------------------------------------------------------------------
    # Shipping address — snapshot at time of order
    # Stored flat so the record is preserved even if user updates address.
    # ------------------------------------------------------------------
    shipping_name     = db.Column(db.String(200), nullable=True)
    shipping_address  = db.Column(db.String(500), nullable=True)
    shipping_city     = db.Column(db.String(100), nullable=True)
    shipping_country  = db.Column(db.String(100), nullable=True)
    shipping_postcode = db.Column(db.String(20),  nullable=True)

    # ------------------------------------------------------------------
    # Timestamps
    # ------------------------------------------------------------------
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    paid_at = db.Column(db.DateTime(timezone=True), nullable=True)

    # ------------------------------------------------------------------
    # Relationships
    # ------------------------------------------------------------------
    user  = db.relationship("User",      back_populates="orders")
    items = db.relationship(
        "OrderItem",
        back_populates="order",
        cascade="all, delete-orphan",
        lazy="joined",
    )

    # ------------------------------------------------------------------
    # Serialisation
    # stripe_payment_intent_id excluded — internal reference only
    # ------------------------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "id":       self.id,
            "status":   self.status,
            "total":    str(self.total),
            "currency": self.currency,
            "items":    [item.to_dict() for item in self.items],
            "shipping": {
                "name":     self.shipping_name,
                "address":  self.shipping_address,
                "city":     self.shipping_city,
                "country":  self.shipping_country,
                "postcode": self.shipping_postcode,
            },
            "created_at": self.created_at.isoformat(),
            "paid_at":    self.paid_at.isoformat() if self.paid_at else None,
        }

    def __repr__(self) -> str:
        return f"<Order {self.id} status={self.status} total={self.total}>"


# -----------------------------------------------------------------------------

class OrderItem(db.Model):
    """
    A single product line within a completed order.

    STRIDE Tampering:
        price_at_purchase is a snapshot of Product.price taken at checkout
        by CheckoutService — never from the request body.
        It preserves exactly what the customer paid even if the product
        price changes later. Immutable after creation.

    This differs from CartItem which stores NO price at all.
    OrderItem MUST store price because orders are permanent financial records.
    """

    __tablename__ = "order_items"

    id         = db.Column(db.Integer, primary_key=True, autoincrement=True)
    order_id   = db.Column(
        db.String(36),
        db.ForeignKey("orders.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    product_id = db.Column(
        db.String(36),
        db.ForeignKey("products.id", ondelete="SET NULL"),
        nullable=True,      # SET NULL preserves order history if product deleted
    )

    # ------------------------------------------------------------------
    # Snapshot fields — copied from Product at checkout, never updated.
    # STRIDE Tampering:   immutable after creation.
    # STRIDE Repudiation: permanent record of what was bought and at what price.
    # ------------------------------------------------------------------
    product_name      = db.Column(db.String(200), nullable=False)  # snapshot
    price_at_purchase = db.Column(Numeric(10, 2), nullable=False)  # snapshot
    quantity          = db.Column(db.Integer,     nullable=False)

    # ------------------------------------------------------------------
    # Relationships
    # ------------------------------------------------------------------
    order   = db.relationship("Order",   back_populates="items")
    product = db.relationship("Product", back_populates="order_items")

    @property
    def subtotal(self) -> Decimal:
        """Line total = price_at_purchase × quantity."""
        return self.price_at_purchase * self.quantity

    def to_dict(self) -> dict:
        return {
            "id":                self.id,
            "product_id":        self.product_id,
            "product_name":      self.product_name,
            "price_at_purchase": str(self.price_at_purchase),
            "quantity":          self.quantity,
            "subtotal":          str(self.subtotal),
        }

    def __repr__(self) -> str:
        return (
            f"<OrderItem {self.product_name} "
            f"x{self.quantity} @ {self.price_at_purchase}>"
        )
