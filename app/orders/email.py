# app/orders/email.py
# Developer 3 — Transactional order emails via SendGrid
#
# Two emails are sent:
#   send_order_confirmation_email() — after Stripe confirms payment succeeded
#   send_order_failed_email()       — after Stripe reports payment failure
#
# Both use HTML + plain-text fallback for maximum email client compatibility.

import logging
from flask import current_app
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Content, MimeType

logger = logging.getLogger(__name__)


def _build_items_table_html(items: list) -> str:
    """Build the HTML table rows for order line items."""
    rows = ""
    for item in items:
        rows += f"""
        <tr>
            <td style="padding:8px 12px; border-bottom:1px solid #e5e7eb;">{item['product_name']}</td>
            <td style="padding:8px 12px; border-bottom:1px solid #e5e7eb; text-align:center;">{item['quantity']}</td>
            <td style="padding:8px 12px; border-bottom:1px solid #e5e7eb; text-align:right;">${item['price_at_purchase']}</td>
            <td style="padding:8px 12px; border-bottom:1px solid #e5e7eb; text-align:right;">${item['subtotal']}</td>
        </tr>"""
    return rows


def _build_items_plain(items: list) -> str:
    """Build the plain-text line items for the fallback email body."""
    lines = []
    for item in items:
        lines.append(
            f"  {item['product_name']} x{item['quantity']} "
            f"@ ${item['price_at_purchase']} = ${item['subtotal']}"
        )
    return "\n".join(lines)


def send_order_confirmation_email(order) -> None:
    """
    Send a payment confirmation email after Stripe webhook confirms success.

    Called from: app/orders/routes.py → stripe_webhook() after payment_intent.succeeded

    Args:
        order: Order model instance (must have .user, .items, .total, .id loaded)
    """
    recipient_email = order.user.email
    recipient_name  = order.user.username or "Customer"
    order_id        = order.id
    order_total     = order.total

    items_html  = _build_items_table_html([item.to_dict() for item in order.items])
    items_plain = _build_items_plain([item.to_dict() for item in order.items])

    shipping = order.shipping_name or ""
    if order.shipping_address:
        shipping += f"\n{order.shipping_address}"
    if order.shipping_city:
        shipping += f"\n{order.shipping_city} {order.shipping_postcode or ''}"

    html_body = f"""
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0; padding:0; background:#f9fafb; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f9fafb; padding:40px 20px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="background:#ffffff; border-radius:8px; overflow:hidden; box-shadow:0 1px 3px rgba(0,0,0,0.1);">

        <!-- Header -->
        <tr>
          <td style="background:#16a34a; padding:32px 40px; text-align:center;">
            <h1 style="margin:0; color:#ffffff; font-size:24px; font-weight:700;">Order Confirmed ✓</h1>
            <p style="margin:8px 0 0; color:#dcfce7; font-size:14px;">Thank you for your purchase!</p>
          </td>
        </tr>

        <!-- Greeting -->
        <tr>
          <td style="padding:32px 40px 16px;">
            <p style="margin:0; font-size:16px; color:#111827;">Hi <strong>{recipient_name}</strong>,</p>
            <p style="margin:12px 0 0; font-size:15px; color:#374151; line-height:1.6;">
              Your payment was successful and your order <strong>#{order_id}</strong> is confirmed.
              We'll send you another email when it ships.
            </p>
          </td>
        </tr>

        <!-- Order Summary Table -->
        <tr>
          <td style="padding:0 40px 24px;">
            <h2 style="margin:0 0 12px; font-size:14px; font-weight:600; color:#6b7280; text-transform:uppercase; letter-spacing:0.05em;">Order Summary</h2>
            <table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #e5e7eb; border-radius:6px; overflow:hidden;">
              <thead>
                <tr style="background:#f3f4f6;">
                  <th style="padding:10px 12px; text-align:left; font-size:13px; color:#374151;">Product</th>
                  <th style="padding:10px 12px; text-align:center; font-size:13px; color:#374151;">Qty</th>
                  <th style="padding:10px 12px; text-align:right; font-size:13px; color:#374151;">Unit Price</th>
                  <th style="padding:10px 12px; text-align:right; font-size:13px; color:#374151;">Total</th>
                </tr>
              </thead>
              <tbody>
                {items_html}
                <tr style="background:#f9fafb;">
                  <td colspan="3" style="padding:12px; text-align:right; font-weight:600; color:#111827;">Order Total</td>
                  <td style="padding:12px; text-align:right; font-weight:700; font-size:16px; color:#16a34a;">${order_total}</td>
                </tr>
              </tbody>
            </table>
          </td>
        </tr>

        <!-- Shipping Address -->
        {'<tr><td style="padding:0 40px 24px;"><h2 style="margin:0 0 8px; font-size:14px; font-weight:600; color:#6b7280; text-transform:uppercase; letter-spacing:0.05em;">Shipping To</h2><p style="margin:0; font-size:14px; color:#374151; white-space:pre-line;">' + shipping + '</p></td></tr>' if shipping.strip() else ''}

        <!-- Footer -->
        <tr>
          <td style="background:#f9fafb; padding:24px 40px; border-top:1px solid #e5e7eb; text-align:center;">
            <p style="margin:0; font-size:13px; color:#6b7280;">
              If you have any questions, reply to this email.<br>
              Order reference: <strong>#{order_id}</strong>
            </p>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
</body>
</html>
"""

    plain_body = f"""
Order Confirmed — #{order_id}

Hi {recipient_name},

Your payment was successful! Here's your order summary:

{items_plain}

Order Total: ${order_total}

{'Shipping to:' + shipping if shipping.strip() else ''}

If you have any questions, reply to this email.
Order reference: #{order_id}
"""

    _send(
        to_email=recipient_email,
        to_name=recipient_name,
        subject=f"Order Confirmed — #{order_id}",
        html_body=html_body,
        plain_body=plain_body,
    )


def send_order_failed_email(order) -> None:
    """
    Send a payment failure notification so the user knows to retry.

    Called from: app/orders/routes.py → stripe_webhook() after payment_intent.payment_failed
    """
    recipient_email = order.user.email
    recipient_name  = order.user.username or "Customer"
    order_id        = order.id

    html_body = f"""
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0; padding:0; background:#f9fafb; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f9fafb; padding:40px 20px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="background:#ffffff; border-radius:8px; overflow:hidden; box-shadow:0 1px 3px rgba(0,0,0,0.1);">

        <!-- Header -->
        <tr>
          <td style="background:#dc2626; padding:32px 40px; text-align:center;">
            <h1 style="margin:0; color:#ffffff; font-size:24px; font-weight:700;">Payment Unsuccessful</h1>
            <p style="margin:8px 0 0; color:#fee2e2; font-size:14px;">Don't worry — your cart is still saved</p>
          </td>
        </tr>

        <!-- Body -->
        <tr>
          <td style="padding:32px 40px;">
            <p style="margin:0; font-size:16px; color:#111827;">Hi <strong>{recipient_name}</strong>,</p>
            <p style="margin:12px 0; font-size:15px; color:#374151; line-height:1.6;">
              Unfortunately, we were unable to process your payment for order <strong>#{order_id}</strong>.
              This can happen for a number of reasons — most commonly an incorrect card number,
              insufficient funds, or a temporary issue with your bank.
            </p>
            <p style="margin:12px 0; font-size:15px; color:#374151;">
              Your cart is still saved. You can go back and try again with a different payment method.
            </p>
            <div style="margin:24px 0; text-align:center;">
              <a href="{current_app.config.get('FRONTEND_URL', '#')}/cart"
                 style="display:inline-block; background:#111827; color:#ffffff; padding:12px 32px;
                        border-radius:6px; text-decoration:none; font-weight:600; font-size:15px;">
                Return to Cart
              </a>
            </div>
          </td>
        </tr>

        <!-- Footer -->
        <tr>
          <td style="background:#f9fafb; padding:24px 40px; border-top:1px solid #e5e7eb; text-align:center;">
            <p style="margin:0; font-size:13px; color:#6b7280;">
              If you continue to experience problems, reply to this email and we'll help.<br>
              Order reference: <strong>#{order_id}</strong>
            </p>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
</body>
</html>
"""

    plain_body = f"""
Payment Unsuccessful — Order #{order_id}

Hi {recipient_name},

Unfortunately your payment for order #{order_id} could not be processed.

Your cart is still saved — you can return to the site and try again
with a different payment method.

{current_app.config.get('FRONTEND_URL', '')}/cart

If you need help, just reply to this email.
Order reference: #{order_id}
"""

    _send(
        to_email=recipient_email,
        to_name=recipient_name,
        subject=f"Payment unsuccessful — Order #{order_id}",
        html_body=html_body,
        plain_body=plain_body,
    )


def _send(to_email: str, to_name: str, subject: str, html_body: str, plain_body: str) -> None:
    """
    Internal send function. Uses SendGrid API.
    Catches and logs errors so a failed email never crashes the webhook response.
    (Stripe expects a 200 from our webhook within 30 seconds — email failure
    should not cause a 500 that triggers Stripe to retry the webhook.)
    """
    try:
        api_key = current_app.config.get("SENDGRID_API_KEY")
        sender  = current_app.config.get("MAIL_DEFAULT_SENDER")

        if not api_key or not sender:
            logger.error("SENDGRID_API_KEY or MAIL_DEFAULT_SENDER not configured — email not sent.")
            return

        message = Mail(
            from_email=sender,
            to_emails=(to_email, to_name),
            subject=subject,
        )
        message.content = [
            Content(MimeType.text, plain_body),
            Content(MimeType.html, html_body),
        ]

        sg = SendGridAPIClient(api_key)
        response = sg.send(message)

        if response.status_code not in (200, 202):
            logger.error(
                f"SendGrid returned unexpected status {response.status_code} "
                f"sending to {to_email}"
            )
        else:
            logger.info(f"Email '{subject}' sent to {to_email}")

    except Exception as e:
        # Never raise — a failed email must not break the webhook
        logger.error(f"Failed to send email to {to_email}: {e}", exc_info=True)
