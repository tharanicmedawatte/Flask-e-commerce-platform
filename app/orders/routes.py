# app/orders/routes.py
# Developer 3 — Orders & Checkout HTTP endpoints
#
# This file is intentionally thin. All business logic lives in services.py.
# Routes only: parse the request → call a service → return JSON.
#
# Endpoints:
#   POST /orders/create-payment-intent   — Step 1 of Stripe flow
#   POST /orders/webhook/stripe          — Step 2 — Stripe calls this after payment
#   GET  /orders/history                 — Paginated order history for logged-in user
#   GET  /orders/<order_id>              — Single order detail
#   GET  /orders/<order_id>/admin        — Admin view of any order
#
# STRIDE coverage:
#   Spoofing           — Stripe webhook HMAC signature verified before processing
#   Tampering          — order totals always from DB via CheckoutService
#   Repudiation        — every event written to AuditLog in services.py
#   Information Disclosure — users can only retrieve their own orders
#   Denial of Service  — rate limiting on create-payment-intent
#   Elevation of Privilege — admin route gated behind @require_role("admin")

import hmac
import hashlib
import logging

import stripe
from flask import Blueprint, request, jsonify, current_app, g

# Import ONLY from app.auth.decorators — Developer 3 never builds auth logic
from app.auth.decorators import login_required, verified_required, require_role

from .services import CheckoutService, OrderService
from .email import send_order_confirmation_email, send_order_failed_email
from app.extensions import limiter

logger = logging.getLogger(__name__)

orders_bp = Blueprint("orders", __name__, url_prefix="/orders")


# =============================================================================
# Step 1 — Create Stripe PaymentIntent
# =============================================================================

@orders_bp.route("/create-payment-intent", methods=["POST"])
@login_required
@verified_required
@limiter.limit("10 per minute")   # STRIDE — DoS: prevent PaymentIntent flood
def create_payment_intent():
    """
    Called by Next.js checkout page after the user clicks "Pay".

    Flow:
        Next.js → POST /orders/create-payment-intent  (with Auth0 Bearer token)
             ← { client_secret, order_id }
        Next.js → Stripe.js confirms payment using client_secret
        Stripe  → POST /orders/webhook/stripe (after card charged)

    Request body (JSON):
        {
          "shipping": {
            "name": "Jane Doe",
            "address_line1": "123 Main St",
            "address_line2": "",        ← optional
            "city": "Colombo",
            "postal_code": "00100",
            "country": "LK"
          }
        }

    STRIDE — Tampering: order total is NEVER in the request body.
    It is always recalculated from live DB prices in CheckoutService.initiate().
    """
    data     = request.get_json(silent=True) or {}
    shipping = data.get("shipping", {})

    # Basic shipping validation
    required_shipping_fields = ["name", "address_line1", "city", "country"]
    missing = [f for f in required_shipping_fields if not shipping.get(f)]
    if missing:
        return jsonify({"error": f"Missing shipping fields: {', '.join(missing)}"}), 400

    order, client_secret, error = CheckoutService.initiate(
        user_id=g.current_user.id,
        shipping=shipping,
    )

    if error:
        return jsonify({"error": error}), 400

    return jsonify({
        "client_secret": client_secret,
        "order_id":      order.id,
        "total":         str(order.total),
    }), 201


# =============================================================================
# Step 2 — Stripe Webhook (payment outcome)
# =============================================================================

@orders_bp.route("/webhook/stripe", methods=["POST"])
def stripe_webhook():
    """
    Stripe calls this URL automatically after a payment succeeds or fails.
    This is the ONLY place we trust that money has moved.

    NEVER trust the frontend to report payment success — always use webhooks.

    STRIDE — Spoofing:
        Stripe signs every webhook with HMAC-SHA256 using your webhook secret.
        We verify the signature with stripe.Webhook.construct_event() before
        touching any data. An invalid signature returns 403 immediately.

    STRIDE — Repudiation:
        Both success and failure are written to AuditLog in services.py.

    This route is @csrf.exempt in app/__init__.py because Stripe cannot
    send a CSRF token. The HMAC signature is our equivalent protection.
    """
    payload   = request.data          # raw bytes — must be raw for signature check
    sig_header = request.headers.get("Stripe-Signature", "")
    webhook_secret = current_app.config.get("STRIPE_WEBHOOK_SECRET")

    if not webhook_secret:
        logger.error("STRIPE_WEBHOOK_SECRET not configured — rejecting webhook.")
        return jsonify({"error": "Webhook not configured"}), 500

    # Verify the HMAC signature — rejects anything not genuinely from Stripe
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, webhook_secret
        )
    except stripe.error.SignatureVerificationError:
        # STRIDE — Spoofing: reject forged/replayed webhooks
        logger.warning("Stripe webhook: invalid signature. Possible spoofing attempt.")
        return jsonify({"error": "Invalid signature"}), 403
    except Exception as e:
        logger.error(f"Stripe webhook parsing error: {e}")
        return jsonify({"error": "Malformed webhook"}), 400

    event_type = event["type"]
    logger.info(f"Stripe webhook received: {event_type}")

    # ── Payment succeeded ────────────────────────────────────────────────────
    if event_type == "payment_intent.succeeded":
        intent     = event["data"]["object"]
        intent_id  = intent["id"]
        charge_id  = intent.get("latest_charge", "")

        success = CheckoutService.confirm_payment(
            payment_intent_id=intent_id,
            stripe_charge_id=charge_id,
        )

        if success:
            # Send confirmation email — errors are caught inside send function
            # so a failed email never causes a non-200 response to Stripe
            from app.models import Order
            order = Order.query.filter_by(stripe_payment_intent_id=intent_id).first()
            if order and order.user:
                send_order_confirmation_email(order)
        else:
            logger.error(f"confirm_payment returned False for intent {intent_id}")

    # ── Payment failed ───────────────────────────────────────────────────────
    elif event_type == "payment_intent.payment_failed":
        intent    = event["data"]["object"]
        intent_id = intent["id"]
        reason    = intent.get("last_payment_error", {}).get("message", "Unknown reason")
        logger.info(f"Payment failed for intent {intent_id}: {reason}")

        CheckoutService.mark_failed(payment_intent_id=intent_id)

        from app.models import Order
        order = Order.query.filter_by(stripe_payment_intent_id=intent_id).first()
        if order and order.user:
            send_order_failed_email(order)

    # ── Other event types (ignored) ──────────────────────────────────────────
    else:
        logger.debug(f"Unhandled Stripe event type: {event_type}")

    # Always return 200 — if we return anything else Stripe will retry
    return jsonify({"status": "ok"}), 200


# =============================================================================
# Order History & Detail
# =============================================================================

@orders_bp.route("/history", methods=["GET"])
@login_required
def order_history():
    """
    Return paginated order history for the logged-in user.

    Query params:
        page     — page number (default 1)
        per_page — results per page (default 10, max 50)

    STRIDE — Information Disclosure: user_id filter ensures users only
    see their own orders. A user cannot enumerate other users' orders
    by guessing order IDs.
    """
    try:
        page     = max(1, int(request.args.get("page", 1)))
        per_page = min(50, max(1, int(request.args.get("per_page", 10))))
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid pagination parameters"}), 400

    result = OrderService.get_order_history(
        user_id=g.current_user.id,
        page=page,
        per_page=per_page,
    )
    return jsonify(result), 200


@orders_bp.route("/<order_id>", methods=["GET"])
@login_required
def order_detail(order_id: str):
    """
    Return a single order with all its line items.

    STRIDE — Information Disclosure: order is scoped to g.current_user.id.
    A user who guesses another user's order ID gets a 404, not the order.
    """
    order = OrderService.get_order(order_id=order_id, user_id=g.current_user.id)
    if not order:
        return jsonify({"error": "Order not found"}), 404
    return jsonify({"order": order.to_dict()}), 200


@orders_bp.route("/<order_id>/admin", methods=["GET"])
@login_required
@require_role("admin")   # STRIDE — Elevation of Privilege: admins only
def order_detail_admin(order_id: str):
    """
    Admin-only: view any order regardless of which user placed it.
    Used for customer support and fulfilment dashboards.
    """
    order = OrderService.get_order_for_admin(order_id=order_id)
    if not order:
        return jsonify({"error": "Order not found"}), 404
    return jsonify({"order": order.to_dict()}), 200
