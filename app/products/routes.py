# =============================================================================
# app/products/routes.py
# Developer 2 — Products Blueprint
#
# Endpoints:
#   GET  /products                 — paginated product list (guest ok)
#   GET  /products/search          — search products (guest ok, rate-limited)
#   GET  /products/<int:id>        — single product detail (guest ok)
#   GET  /cart                     — get current user's cart (login required)
#   POST /cart                     — add item to cart (login required)
#   PUT  /cart/<int:item_id>       — update cart item quantity (login required)
#   DELETE /cart/<int:item_id>     — remove cart item (login required)
#
# Auth decorators are ALWAYS imported from app.auth.decorators.
# We never build our own authentication logic here.
# =============================================================================

from flask import jsonify, request
from flask_limiter.util import get_remote_address

from app.auth.decorators import guest_or_user, login_required  # Dev 1 / shared auth
from app.extensions import limiter                              # Flask-Limiter on extensions.py

from . import products_bp                                       # blueprint instance
from .services import CartService, ProductService

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ok(data: dict | list, status: int = 200):
    """Thin wrapper — keeps every success response uniform for Next.js."""
    return jsonify({"status": "success", "data": data}), status


def _err(message: str, status: int = 400):
    """Thin wrapper — keeps every error response uniform for Next.js."""
    return jsonify({"status": "error", "message": message}), status


def _parse_int_param(name: str, default: int, min_val: int = 1, max_val: int = 9999) -> int:
    """
    Parse an integer query-string param safely.

    STRIDE — Tampering / DoS:
      Rejects non-integer strings and clamps the result to [min_val, max_val].
      Callers never receive a raw, unvalidated integer from request.args.
    """
    try:
        val = int(request.args.get(name, default))
    except (ValueError, TypeError):
        val = default
    return max(min_val, min(val, max_val))


# =============================================================================
# Product Routes — guest access allowed
# @guest_or_user: Auth0 token is decoded if present, but absence is not an
# error. Useful so Next.js can show personalised UI while still serving
# anonymous visitors.
# =============================================================================

@products_bp.route("/products", methods=["GET"])
@guest_or_user
def list_products():
    """
    GET /products
    Query params (all optional, all sanitised/clamped server-side):
      page          int   default 1
      per_page      int   default 12, max 50
      category      str   category slug
      min_price     float
      max_price     float
      sort          str   newest | oldest | price_asc | price_desc | name_asc

    STRIDE — DoS: page/per_page clamped inside ProductService.get_all().
    STRIDE — Tampering: sort validated against whitelist in service layer.
    STRIDE — Information Disclosure: to_dict() whitelists returned fields;
      cost_price and supplier are never included.
    """
    page     = _parse_int_param("page",     default=1,  min_val=1, max_val=1_000)
    per_page = _parse_int_param("per_page", default=12, min_val=1, max_val=50)

    # Price params — parse to float; service layer validates further
    def _safe_float(name):
        try:
            return float(request.args.get(name))
        except (TypeError, ValueError):
            return None

    result = ProductService.get_all(
        page          = page,
        per_page      = per_page,
        category_slug = request.args.get("category", "").strip() or None,
        min_price     = _safe_float("min_price"),
        max_price     = _safe_float("max_price"),
        sort          = request.args.get("sort", "newest"),
    )
    return _ok(result)


@products_bp.route("/products/search", methods=["GET"])
@guest_or_user
# STRIDE — Denial of Service:
#   Rate-limit the search endpoint specifically because LIKE queries are more
#   expensive than PK lookups.  Limits are per-IP (get_remote_address).
#   "30 per minute" throttles automated scraping / brute-force enumeration.
#   "5 per second" prevents burst floods.
@limiter.limit("30 per minute; 5 per second", key_func=get_remote_address)
def search_products():
    """
    GET /products/search?q=<term>&page=1&per_page=12

    STRIDE — DoS:
      • Rate-limited at the decorator level (30/min, 5/sec per IP).
      • 'q' is sanitised and truncated inside ProductService.search().
      • page / per_page clamped inside service layer.

    STRIDE — Information Disclosure:
      Sanitised query is echoed back in the response so the frontend can
      display "Results for: <term>" — but it is the CLEANED value, not the
      raw user input.
    """
    raw_query = request.args.get("q", "")
    page      = _parse_int_param("page",     default=1,  min_val=1, max_val=1_000)
    per_page  = _parse_int_param("per_page", default=12, min_val=1, max_val=50)

    result = ProductService.search(
        query    = raw_query,
        page     = page,
        per_page = per_page,
    )
    return _ok(result)


@products_bp.route("/products/<product_id>", methods=["GET"])
@guest_or_user
def get_product(product_id: str):
    """
    GET /products/<id>

    STRIDE — Information Disclosure:
      to_dict() in the service layer ensures cost_price / supplier are never
      included in the response, even for a direct ID lookup.

    product_id is a UUID string — the <product_id> string converter is correct.
    SQLAlchemy's ORM parameterises the value, preventing SQL injection.
    """
    product = ProductService.get_by_id(product_id)
    if not product:
        return _err("product not found", 404)
    return _ok(product)


# =============================================================================
# Cart Routes — login required
# @login_required: validates Auth0 Bearer token; returns 401 if absent or invalid.
# We never implement token validation ourselves.
# =============================================================================

@products_bp.route("/cart", methods=["GET"])
@login_required
def get_cart():
    """
    GET /cart

    Returns the authenticated user's full cart with a server-calculated total.

    STRIDE — Elevation of Privilege:
      user_id is read from the Auth0-validated token (g.current_user),
      never from the request body or query string.

    STRIDE — Information Disclosure:
      Cart.to_dict() → CartItem.to_dict() → whitelisted product fields only.
    """
    from flask import g
    cart = CartService.get_cart(user_id=g.current_user.id)
    return _ok(cart)


@products_bp.route("/cart", methods=["POST"])
@login_required
def add_to_cart():
    """
    POST /cart
    Body (JSON): { "product_id": int, "quantity": int }

    STRIDE — Tampering:
      • 'price' is intentionally NOT read from the request body.
        unit_price is resolved server-side from Product.sell_price.
      • product_id and quantity are the only accepted fields.

    STRIDE — Elevation of Privilege:
      user_id from Auth0 token only — never from request body.
    """
    from flask import g

    body = request.get_json(silent=True) or {}

    # STRIDE — Tampering: extract only product_id and quantity; ignore everything else.
    # Dev 1: Product.id is String(36) UUID — no int conversion.
    product_id = body.get("product_id")
    if not product_id or not isinstance(product_id, str):
        return _err("product_id must be a UUID string", 400)

    # Default quantity to 1 if omitted — service layer validates the value
    raw_qty  = body.get("quantity", 1)

    cart, error = CartService.add_item(
        user_id    = g.current_user.id,
        product_id = product_id,
        quantity   = raw_qty,
        # NOTE: no 'price' argument — price is never accepted from the client
    )

    if error:
        return _err(error, 400)

    return _ok(cart, 201)


@products_bp.route("/cart/<int:item_id>", methods=["PUT"])
@login_required
def update_cart_item(item_id: int):
    """
    PUT /cart/<item_id>
    Body (JSON): { "quantity": int }

    Setting quantity to 0 removes the item (convenience alias for DELETE).

    STRIDE — Elevation of Privilege:
      CartService.update_item() joins CartItem → Cart and checks Cart.user_id
      matches the token user, so one user cannot mutate another's cart item.

    STRIDE — Tampering:
      Only 'quantity' is read; no price field is accepted.
    """
    from flask import g

    body = request.get_json(silent=True) or {}

    if "quantity" not in body:
        return _err("quantity is required", 400)

    cart, error = CartService.update_item(
        user_id  = g.current_user.id,
        item_id  = item_id,
        quantity = body.get("quantity"),
    )

    if error:
        # 404 for ownership violations — don't reveal whether the item
        # exists at all for a different user (STRIDE — Information Disclosure)
        status = 404 if "not found" in error else 400
        return _err(error, status)

    return _ok(cart)


@products_bp.route("/cart/<int:item_id>", methods=["DELETE"])
@login_required
def remove_cart_item(item_id: int):
    """
    DELETE /cart/<item_id>

    STRIDE — Elevation of Privilege:
      CartService.remove_item() verifies the item belongs to the token user
      before deleting. Returns 404 regardless of whether the item exists or
      belongs to someone else — no oracle for item enumeration.
    """
    from flask import g

    cart, error = CartService.remove_item(
        user_id = g.current_user.id,
        item_id = item_id,
    )

    if error:
        return _err(error, 404)

    return _ok(cart)