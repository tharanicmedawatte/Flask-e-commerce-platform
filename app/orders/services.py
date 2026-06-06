# app/orders/services.py
# Developer 3 — Checkout & Order business logic
#
# This file contains ALL business logic for checkout and orders.
# Routes call these services — routes themselves have no logic.
#
# STRIDE coverage in this file:
#   Tampering          — prices always recalculated from DB, never from client
#   Repudiation        — every payment event written to AuditLog
#   Information Disclosure — Stripe transaction IDs logged, card details never stored

import stripe
from decimal import Decimal
from datetime import datetime, timezone

from flask import current_app
from app.extensions import db
from app.models import Cart, CartItem, Order, OrderItem, OrderStatus, Product, AuditLog


class CheckoutService:
    """
    Handles the two-step Stripe payment flow:

    Step 1 — initiate():
        Validate cart → calculate total from DB → create Order (status=PENDING)
        → create Stripe PaymentIntent → return client_secret to Next.js

    Step 2 — confirm_payment() / mark_failed():
        Called by the webhook route after Stripe confirms outcome.
        Money has moved. Update order status and write AuditLog.

    The frontend NEVER tells us what the total is.
    We always calculate it ourselves from live database prices.
    STRIDE — Tampering.
    """

    @staticmethod
    def initiate(user_id: int, shipping: dict) -> tuple:
        """
        Validate cart, build the order, create a Stripe PaymentIntent.

        Returns:
            (order, client_secret, error_message)
            On success: (Order, "pi_xxx_secret_xxx", None)
            On failure: (None, None, "reason string")
        """
        stripe.api_key = current_app.config["STRIPE_SECRET_KEY"]

        # 1. Load the cart
        cart = Cart.query.filter_by(user_id=user_id).first()
        if not cart or not cart.items:
            return None, None, "Your cart is empty."

        # 2. Validate every item and recalculate total from live DB prices
        #    STRIDE — Tampering: we never use any price submitted by the client
        total = Decimal("0.00")
        validated_items = []

        for cart_item in cart.items:
            product = Product.query.get(cart_item.product_id)
            if not product:
                return None, None, f"A product in your cart is no longer available."
            if not product.is_visible:
                return None, None, f"'{product.name}' is no longer available."
            if product.stock < cart_item.quantity:
                return None, None, (
                    f"Only {product.stock} unit(s) of '{product.name}' are in stock. "
                    f"You requested {cart_item.quantity}."
                )
            line_total = product.price * cart_item.quantity
            total += line_total
            validated_items.append({
                "product":          product,
                "quantity":         cart_item.quantity,
                "price_at_purchase": product.price,  # snapshot at this moment
                "product_name":     product.name,    # snapshot in case name changes
            })

        if total <= 0:
            return None, None, "Order total must be greater than zero."

        # 3. Create the Order row (status=PENDING — no money moved yet)
        order = Order(
            user_id=user_id,
            status=OrderStatus.PENDING,
            total=total,
            shipping_name=shipping.get("name"),
            shipping_address_line1=shipping.get("address_line1"),
            shipping_address_line2=shipping.get("address_line2"),
            shipping_city=shipping.get("city"),
            shipping_postal_code=shipping.get("postal_code"),
            shipping_country=shipping.get("country"),
        )
        db.session.add(order)
        db.session.flush()  # get order.id without committing yet

        # 4. Create OrderItems — frozen price snapshots
        for item_data in validated_items:
            order_item = OrderItem(
                order_id=order.id,
                product_id=item_data["product"].id,
                product_name=item_data["product_name"],
                price_at_purchase=item_data["price_at_purchase"],
                quantity=item_data["quantity"],
            )
            db.session.add(order_item)

        # 5. Create Stripe PaymentIntent
        #    Amount is in cents — Stripe does not use decimals
        #    STRIDE — Tampering: amount comes from our DB total, not the request body
        try:
            intent = stripe.PaymentIntent.create(
                amount=int(total * 100),  # e.g. $19.99 → 1999
                currency="usd",
                automatic_payment_methods={"enabled": True},
                metadata={
                    "order_id": order.id,
                    "user_id":  user_id,
                },
            )
        except stripe.error.StripeError as e:
            db.session.rollback()
            current_app.logger.error(f"Stripe PaymentIntent creation failed: {e}")
            return None, None, "Payment service unavailable. Please try again."

        # 6. Store the PaymentIntent ID so we can match it in the webhook
        order.stripe_payment_intent_id = intent.id
        db.session.commit()

        # 7. Audit log — STRIDE Repudiation
        AuditLog.record(
            event="CHECKOUT_INITIATED",
            user_id=user_id,
            details=f"Order #{order.id} | total=${total} | intent={intent.id}",
        )

        return order, intent.client_secret, None

    @staticmethod
    def confirm_payment(payment_intent_id: str, stripe_charge_id: str) -> bool:
        """
        Called by the Stripe webhook after payment_intent.succeeded event.
        Marks the order as PAID, decrements stock, clears the cart.

        STRIDE — Repudiation: payment confirmation written to AuditLog.
        STRIDE — Information Disclosure: only last 4 digits and charge ID logged,
        never full card details (which Stripe never sends us anyway).

        Returns True on success, False if order not found or already processed.
        """
        order = Order.query.filter_by(
            stripe_payment_intent_id=payment_intent_id
        ).first()

        if not order:
            current_app.logger.error(
                f"Webhook: PaymentIntent {payment_intent_id} matched no order."
            )
            return False

        if order.status != OrderStatus.PENDING:
            # Already processed — idempotent handling (Stripe may retry webhooks)
            current_app.logger.warning(
                f"Webhook: Order #{order.id} already has status {order.status.value}. Skipping."
            )
            return True

        # Update order
        order.status = OrderStatus.PAID
        order.stripe_transaction_id = stripe_charge_id
        order.paid_at = datetime.now(timezone.utc)

        # Decrement stock for each item
        for item in order.items:
            if item.product:
                item.product.stock = max(0, item.product.stock - item.quantity)

        # Clear the user's cart
        if order.user_id:
            cart = Cart.query.filter_by(user_id=order.user_id).first()
            if cart:
                CartItem.query.filter_by(cart_id=cart.id).delete()

        db.session.commit()

        # STRIDE — Repudiation: log the confirmation
        AuditLog.record(
            event="PAYMENT_CONFIRMED",
            user_id=order.user_id,
            details=f"Order #{order.id} | charge={stripe_charge_id}",
        )

        return True

    @staticmethod
    def mark_failed(payment_intent_id: str) -> bool:
        """
        Called by the Stripe webhook after payment_intent.payment_failed event.
        Marks the order as FAILED. Cart is NOT cleared — user can retry.

        STRIDE — Repudiation: failure written to AuditLog.
        """
        order = Order.query.filter_by(
            stripe_payment_intent_id=payment_intent_id
        ).first()

        if not order:
            return False

        if order.status != OrderStatus.PENDING:
            return True  # idempotent

        order.status = OrderStatus.FAILED
        db.session.commit()

        AuditLog.record(
            event="PAYMENT_FAILED",
            user_id=order.user_id,
            details=f"Order #{order.id} | intent={payment_intent_id}",
        )

        return True


class OrderService:
    """
    Read-only queries for order history and detail views.
    """

    @staticmethod
    def get_order_history(user_id: int, page: int = 1, per_page: int = 10) -> dict:
        """
        Return paginated order history for a user.
        Newest orders first.
        """
        pagination = (
            Order.query
            .filter_by(user_id=user_id)
            .order_by(Order.created_at.desc())
            .paginate(page=page, per_page=per_page, error_out=False)
        )
        return {
            "orders":      [o.to_dict() for o in pagination.items],
            "total":       pagination.total,
            "page":        pagination.page,
            "pages":       pagination.pages,
            "per_page":    pagination.per_page,
            "has_next":    pagination.has_next,
            "has_prev":    pagination.has_prev,
        }

    @staticmethod
    def get_order(order_id: int, user_id: int):
        """
        Get a single order, scoped to the requesting user.
        Returns None if order doesn't exist or belongs to a different user.
        STRIDE — Information Disclosure: users can only see their own orders.
        """
        return Order.query.filter_by(id=order_id, user_id=user_id).first()

    @staticmethod
    def get_order_for_admin(order_id: int):
        """Admin-only: get any order regardless of user."""
        return Order.query.get(order_id)
