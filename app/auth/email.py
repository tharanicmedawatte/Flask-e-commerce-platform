# app/auth/email.py
# All transactional emails for the auth blueprint.
# Uses Flask-Mail (SMTP). Swap the send() call for an API like SendGrid by
# changing only this file — routes and services stay untouched.

from flask import current_app, url_for, render_template_string
from flask_mail import Message

from app.extensions import mail


# ---------------------------------------------------------------------------
# Internal send helper
# ---------------------------------------------------------------------------

def _send(subject: str, recipient: str, html_body: str, text_body: str) -> None:
    """
    Build and dispatch a Flask-Mail Message.
    Sends both HTML and plain-text parts (plain-text is the fallback for
    email clients that block HTML — important for deliverability).
    """
    sender = current_app.config.get("MAIL_DEFAULT_SENDER", "noreply@example.com")
    msg = Message(subject=subject, sender=sender, recipients=[recipient])
    msg.body = text_body
    msg.html = html_body
    mail.send(msg)


# ---------------------------------------------------------------------------
# HTML template helpers
# ---------------------------------------------------------------------------

_BASE_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{subject}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #f4f4f5; margin: 0; padding: 0; color: #18181b; }}
    .wrapper {{ max-width: 560px; margin: 40px auto; background: #ffffff;
                border-radius: 8px; overflow: hidden;
                box-shadow: 0 1px 3px rgba(0,0,0,.12); }}
    .header  {{ background: #18181b; padding: 28px 36px; }}
    .header h1 {{ color: #ffffff; margin: 0; font-size: 22px; font-weight: 600; }}
    .body    {{ padding: 32px 36px; }}
    .body p  {{ line-height: 1.7; margin: 0 0 16px; font-size: 15px; color: #3f3f46; }}
    .btn     {{ display: inline-block; padding: 12px 28px; background: #18181b;
                color: #ffffff !important; text-decoration: none;
                border-radius: 6px; font-size: 15px; font-weight: 500;
                margin: 8px 0 20px; }}
    .footer  {{ padding: 20px 36px; border-top: 1px solid #e4e4e7; }}
    .footer p {{ font-size: 12px; color: #a1a1aa; margin: 0; line-height: 1.6; }}
  </style>
</head>
<body>
<div class="wrapper">
  <div class="header"><h1>ShopName</h1></div>
  <div class="body">{body}</div>
  <div class="footer">
    <p>You received this email because an account was created with this address.<br>
       If you did not sign up, you can safely ignore this message.</p>
  </div>
</div>
</body>
</html>
"""


def _wrap_html(subject: str, body_html: str) -> str:
    return _BASE_HTML.format(subject=subject, body=body_html)


# ---------------------------------------------------------------------------
# Public email functions
# ---------------------------------------------------------------------------

def send_verification_email(user) -> None:
    """
    Send a welcome + email-verification email to a newly registered user.

    The verification link is time-limited (24 h) and single-use.
    The token is generated before calling this function (in AuthService.register)
    and stored on the user row.

    STRIDE — Information Disclosure:
      Token travels over HTTPS only (Flask-Talisman enforces this).
      The link does not embed the user's email or id — only the opaque token.
    """
    verify_url = url_for(
        "auth.verify_email",
        token=user.verification_token,
        _external=True,
        _scheme="https",
    )

    subject = "Welcome! Please verify your email address"

    html_body = _wrap_html(
        subject,
        f"""\
        <p>Hi <strong>{user.username}</strong>,</p>
        <p>Welcome to ShopName! Your account has been created successfully.</p>
        <p>Please verify your email address to unlock all features.
           This link expires in <strong>24 hours</strong>.</p>
        <a href="{verify_url}" class="btn">Verify my email</a>
        <p>Or copy this link into your browser:</p>
        <p style="word-break:break-all;font-size:13px;color:#71717a;">{verify_url}</p>
        """,
    )

    text_body = (
        f"Hi {user.username},\n\n"
        "Welcome to ShopName! Your account has been created successfully.\n\n"
        "Please verify your email address (link expires in 24 hours):\n"
        f"{verify_url}\n\n"
        "If you did not sign up, please ignore this email.\n"
    )

    _send(subject, user.email, html_body, text_body)


def send_account_confirmed_email(user) -> None:
    """
    Optional follow-up email sent once the user clicks the verification link
    and their account is fully activated.
    """
    subject = "Your account is now active"

    html_body = _wrap_html(
        subject,
        f"""\
        <p>Hi <strong>{user.username}</strong>,</p>
        <p>Your email address has been verified and your account is fully active.</p>
        <p>You can now log in and start shopping.</p>
        <a href="{url_for('auth.login', _external=True, _scheme='https')}"
           class="btn">Log in now</a>
        """,
    )

    text_body = (
        f"Hi {user.username},\n\n"
        "Your email address has been verified and your account is fully active.\n\n"
        f"Log in: {url_for('auth.login', _external=True, _scheme='https')}\n"
    )

    _send(subject, user.email, html_body, text_body)


def send_login_alert_email(user, ip_address: str) -> None:
    """
    Security alert sent on every successful login.
    Helps users spot account takeover attempts early.
    """
    subject = "New sign-in to your account"

    from datetime import datetime, timezone
    timestamp = datetime.now(timezone.utc).strftime("%d %b %Y at %H:%M UTC")

    html_body = _wrap_html(
        subject,
        f"""\
        <p>Hi <strong>{user.username}</strong>,</p>
        <p>A new sign-in to your ShopName account was detected:</p>
        <p><strong>Time:</strong> {timestamp}<br>
           <strong>IP address:</strong> {ip_address}</p>
        <p>If this was you, no action is needed.
           If you don't recognise this activity, please
           <a href="{url_for('auth.logout', _external=True, _scheme='https')}">
           log out all sessions</a> and change your password immediately.</p>
        """,
    )

    text_body = (
        f"Hi {user.username},\n\n"
        f"A new sign-in was detected on your account.\n"
        f"Time: {timestamp}\nIP address: {ip_address}\n\n"
        "If this wasn't you, log out and change your password immediately.\n"
    )

    _send(subject, user.email, html_body, text_body)
