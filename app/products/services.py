# =============================================================================
# app/products/services.py
# Developer 2 — Products Blueprint
#
# Aligned to Dev 1's models.py (May 2026 version):
#   Product  → .price  (not .sell_price), .stock (not .stock_qty)
#   CartItem → NO unit_price field; price always live from Product.price
#   Cart.id  → String(36) UUID  |  User.id → String(36) UUID
#   Cart.items → lazy="joined"  (plain list, not a dynamic query)
# =============================================================================

from __future__ import annotations

import re
from decimal import Decimal
from typing import Optional

from sqlalchemy import or_

from app.extensions import db
from app.models import Cart, CartItem, Category, Product

# ---------------------------------------------------------------------------
# Constants
# STRIDE — Denial of Service: hard caps on every user-controlled input.
# ---------------------------------------------------------------------------
MAX_SEARCH_LENGTH = 100
MAX_PAGE_SIZE     = 50
DEFAULT_PAGE_SIZE = 12
MAX_PAGE_NUMBER   = 1_000


# =============================================================================
# ProductService
# =============================================================================
class ProductService:

    @staticmethod
    def _sanitise_search(raw: str) -> str:
        """
        STRIDE — DoS / Tampering:
          Strip whitespace, collapse spaces, remove LIKE metacharacters (%_\\),
          and hard-truncate to MAX_SEARCH_LENGTH.
        """
        clean = raw.strip()
        clean = re.sub(r"\s+", " ", clean)
        clean = re.sub(r"[%_\\]", "", clean)
        return clean[:MAX_SEARCH_LENGTH]

    @staticmethod
    def _clamp_pagination(page: int, per_page: int) -> tuple[int, int]:
        """STRIDE — DoS: clamp page and per_page to sane ranges."""
        page     = max(1, min(page, MAX_PAGE_NUMBER))
        per_page = max(1, min(per_page, MAX_PAGE_SIZE))
        return page, per_page

    @staticmethod
    def _base_query():
        """Only active products are ever surfaced to end users."""
        return Product.query.filter(Product.is_active == True)  # noqa: E712

    # ------------------------------------------------------------------
    # Public API — browsing
    # ------------------------------------------------------------------

    @staticmethod
    def get_all(
        page: int = 1,
        per_page: int = DEFAULT_PAGE_SIZE,
        category_slug: Optional[str] = None,
        min_price: Optional[float] = None,
        max_price: Optional[float] = None,
        sort: str = "newest",
    ) -> dict:
        """
        Paginated active-product list with optional filters.

        STRIDE — DoS:      page/per_page clamped.
        STRIDE — Tampering: sort validated against whitelist only.
        STRIDE — Info Disclosure: to_dict() whitelists returned fields.
        """
        page, per_page = ProductService._clamp_pagination(page, per_page)
        q = ProductService._base_query()

        if category_slug:
            # STRIDE — SQL Injection: ORM parameterises the slug value.
            q = q.join(Category).filter(Category.slug == category_slug)

        if min_price is not None:
            try:
                # Dev 1 field: Product.price  (not sell_price)
                q = q.filter(Product.price >= Decimal(str(min_price)))
            except Exception:
                pass

        if max_price is not None:
            try:
                q = q.filter(Product.price <= Decimal(str(max_price)))
            except Exception:
                pass

        # STRIDE — Tampering: whitelist prevents arbitrary ORDER BY injection.
        sort_map = {
            "newest":     Product.created_at.desc(),
            "oldest":     Product.created_at.asc(),
            "price_asc":  Product.price.asc(),    # Dev 1 field: .price
            "price_desc": Product.price.desc(),
            "name_asc":   Product.name.asc(),
        }
        q = q.order_by(sort_map.get(sort, Product.created_at.desc()))

        paginated = q.paginate(page=page, per_page=per_page, error_out=False)

        return {
            "items":       [p.to_dict() for p in paginated.items],
            "total":       paginated.total,
            "page":        paginated.page,
            "per_page":    paginated.per_page,
            "total_pages": paginated.pages,
            "has_next":    paginated.has_next,
            "has_prev":    paginated.has_prev,
        }

    @staticmethod
    def get_by_id(product_id: str) -> Optional[dict]:
        """
        Fetch a single active product by its UUID primary key.
        Returns None → 404 in route.

        STRIDE — Info Disclosure: to_dict() never includes cost_price.
        """
        # Dev 1: Product.id is String(36) UUID — no int cast needed.
        product = ProductService._base_query().filter(
            Product.id == product_id
        ).first()
        return product.to_dict() if product else None

    @staticmethod
    def search(
        query: str,
        page: int = 1,
        per_page: int = DEFAULT_PAGE_SIZE,
    ) -> dict:
        """
        Search across name, description, and SKU.

        STRIDE — DoS:           rate-limited in routes.py + sanitised here.
        STRIDE — SQL Injection: ORM .ilike() uses parameterised queries.
        """
        clean_query = ProductService._sanitise_search(query)

        if not clean_query:
            return {
                "items": [], "total": 0, "page": 1,
                "per_page": per_page, "total_pages": 0,
                "has_next": False, "has_prev": False, "query": "",
            }

        page, per_page = ProductService._clamp_pagination(page, per_page)
        pattern = f"%{clean_query}%"

        q = ProductService._base_query().filter(
            or_(
                Product.name.ilike(pattern),
                Product.description.ilike(pattern),
                Product.sku.ilike(pattern),
            )
        ).order_by(Product.name.asc())

        paginated = q.paginate(page=page, per_page=per_page, error_out=False)

        return {
            "items":       [p.to_dict() for p in paginated.items],
            "total":       paginated.total,
            "page":        paginated.page,
            "per_page":    paginated.per_page,
            "total_pages": paginated.pages,
            "has_next":    paginated.has_next,
            "has_prev":    paginated.has_prev,
            "query":       clean_query,
        }


# =============================================================================
# CartService
# =============================================================================
class CartService:
    """
    Cart logic aligned to Dev 1's schema:
      - CartItem has NO unit_price; price is always live from Product.price
      - Cart.items is lazy="joined" — it is a plain list, never call .all()
      - Cart.calculate_total() is defined on the model — we use it directly
      - Cart.id and User.id are both String(36) UUIDs
    """

    @staticmethod
    def _get_or_create_cart(user_id: str) -> Cart:
        """Retrieve or create the user's cart (one per user, DB-enforced)."""
        cart = Cart.query.filter_by(user_id=user_id).first()
        if not cart:
            cart = Cart(user_id=user_id)
            db.session.add(cart)
            db.session.flush()
        return cart

    @staticmethod
    def _get_active_product(product_id: str) -> Optional[Product]:
        """Return the product only if it exists and is currently active."""
        # Dev 1: Product.id is String(36) UUID
        return Product.query.filter_by(id=product_id, is_active=True).first()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @staticmethod
    def get_cart(user_id: str) -> dict:
        """Return the user's current cart."""
        cart = CartService._get_or_create_cart(user_id)
        db.session.commit()
        # Dev 1's Cart.to_dict() calculates total live from Product.price
        return cart.to_dict()

    @staticmethod
    def add_item(user_id: str, product_id: str, quantity: int = 1) -> tuple[dict, str]:
        """
        Add a product to the cart, or increment quantity if already present.

        STRIDE — Tampering:
          No price is accepted from the caller.
          Dev 1's CartItem has NO unit_price column — price is always read
          live from Product.price at serialisation time (Cart.calculate_total).

        STRIDE — DoS: quantity capped at 9999 and validated as positive int.
        """
        try:
            quantity = int(quantity)
        except (TypeError, ValueError):
            return {}, "quantity must be an integer"

        if quantity < 1:
            return {}, "quantity must be at least 1"

        if quantity > 9999:
            return {}, "quantity cannot exceed 9999"

        product = CartService._get_active_product(product_id)
        if not product:
            return {}, "product not found or unavailable"

        # Dev 1: Product.is_in_stock(qty) and Product.stock
        if not product.is_in_stock(quantity):
            return {}, f"only {product.stock} units available"

        cart = CartService._get_or_create_cart(user_id)

        existing_item = CartItem.query.filter_by(
            cart_id=cart.id, product_id=product_id
        ).first()

        if existing_item:
            new_qty = existing_item.quantity + quantity
            if not product.is_in_stock(new_qty):
                return {}, f"cannot add {quantity} more — only {product.stock} in stock"
            existing_item.quantity = new_qty
            # No unit_price to refresh — Dev 1's model reads price live from Product.
        else:
            item = CartItem(
                cart_id    = cart.id,
                product_id = product_id,
                quantity   = quantity,
                # STRIDE — Tampering: no price column on CartItem.
                # Total is always calculated from Product.price server-side.
            )
            db.session.add(item)

        db.session.commit()
        return cart.to_dict(), ""

    @staticmethod
    def update_item(user_id: str, item_id: int, quantity: int) -> tuple[dict, str]:
        """
        Set a cart item's quantity. Setting quantity to 0 removes the item.

        STRIDE — Elevation of Privilege:
          Ownership verified via join to Cart → user_id before any mutation.

        STRIDE — Tampering: only quantity is accepted; no price field.
        """
        try:
            quantity = int(quantity)
        except (TypeError, ValueError):
            return {}, "quantity must be an integer"

        if quantity < 0:
            return {}, "quantity cannot be negative"

        if quantity > 9999:
            return {}, "quantity cannot exceed 9999"

        # STRIDE — Elevation of Privilege: join enforces ownership.
        item = (
            CartItem.query
            .join(Cart)
            .filter(CartItem.id == item_id, Cart.user_id == user_id)
            .first()
        )

        if not item:
            return {}, "cart item not found"

        if quantity == 0:
            db.session.delete(item)
            db.session.commit()
            return CartService.get_cart(user_id), ""

        product = CartService._get_active_product(item.product_id)
        if not product:
            return {}, "product is no longer available"

        # Dev 1: Product.stock
        if quantity > product.stock:
            return {}, f"only {product.stock} units available"

        item.quantity = quantity
        db.session.commit()
        return CartService.get_cart(user_id), ""

    @staticmethod
    def remove_item(user_id: str, item_id: int) -> tuple[dict, str]:
        """
        Remove a single item from the cart.

        STRIDE — Elevation of Privilege + Info Disclosure:
          Returns 404 regardless of whether item_id exists or belongs to
          someone else — no oracle for enumerating other users' carts.
        """
        item = (
            CartItem.query
            .join(Cart)
            .filter(CartItem.id == item_id, Cart.user_id == user_id)
            .first()
        )

        if not item:
            return {}, "cart item not found"

        cart = item.cart
        db.session.delete(item)
        db.session.commit()
        return cart.to_dict(), ""

    @staticmethod
    def clear_cart(user_id: str) -> dict:
        """Remove all items from the user's cart; keep the Cart row itself."""
        cart = Cart.query.filter_by(user_id=user_id).first()
        if cart:
            # Dev 1: Cart.items is a list (lazy=joined) — iterate to delete
            for item in list(cart.items):
                db.session.delete(item)
            db.session.commit()
        return {"message": "cart cleared"}