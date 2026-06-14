# =============================================================================
# app/auth/services.py
# Business logic for Auth0 token verification and user synchronisation.
#
# What this file does:
#   1. Verifies Auth0 JWT tokens (proves the request is genuinely from Auth0)
#   2. Syncs the Auth0 user into our MySQL database on first login
#   3. Updates the user row on subsequent logins (last_login_at, is_verified)
#   4. Writes every event to AuditLog
#
# What this file does NOT do:
#   - No custom login, register, or password logic — Auth0 owns all of that
#   - No session management — Flask-Login handles sessions
#   - No HTTP request/response objects — that belongs in routes.py
#
# Auth0 JWT verification flow:
#   1. User logs in on the Next.js frontend via Auth0 Universal Login
#   2. Auth0 returns a JWT access token to Next.js
#   3. Next.js sends that token to Flask in: Authorization: Bearer <token>
#   4. Flask calls Auth0TokenService.verify() to validate the token
#   5. Auth0 publishes its public signing keys at a well-known URL (JWKS)
#   6. We fetch those keys and use them to verify the token signature
#   7. If valid, we trust the claims inside the token (sub, email, etc.)
#
# Dependencies:
#   pip install python-jose[cryptography] requests
# =============================================================================

import logging
from datetime import datetime, timezone

import requests
from flask import current_app, request as flask_request
from jose import ExpiredSignatureError, JWTError, jwt

from app.extensions import db
from app.models import AuditLog, User

logger = logging.getLogger(__name__)


# =============================================================================
# Auth0TokenService
# Handles all interaction with Auth0's token infrastructure.
# =============================================================================

class Auth0TokenService:
    """
    Verifies Auth0 JWT access tokens.

    STRIDE Spoofing:
      We never trust a token's claims without cryptographic verification.
      Auth0 signs every token with its private key.
      We fetch Auth0's public keys (JWKS) and verify the signature.
      A forged or tampered token will fail signature verification.

    STRIDE Info Disclosure:
      We cache the JWKS response to avoid leaking request patterns and
      to reduce latency. Cache is invalidated when a key ID is not found
      (Auth0 rotates keys periodically).
    """

    # In-memory JWKS cache — key: Auth0 domain, value: JWKS dict
    # Resets on server restart; populated lazily on first request.
    _jwks_cache: dict = {}

    @classmethod
    def _get_jwks(cls, domain: str) -> dict:
        """
        Fetch Auth0's public signing keys (JWKS).
        Cached in memory to avoid an HTTP request on every API call.

        STRIDE DoS: if Auth0 is unreachable, returns None gracefully
        rather than crashing the application.
        """
        if domain in cls._jwks_cache:
            return cls._jwks_cache[domain]

        jwks_url = f"https://{domain}/.well-known/jwks.json"
        try:
            response = requests.get(jwks_url, timeout=5)
            response.raise_for_status()
            jwks = response.json()
            cls._jwks_cache[domain] = jwks
            logger.info(f"[Auth0] Fetched and cached JWKS from {jwks_url}")
            return jwks
        except requests.RequestException as exc:
            logger.error(f"[Auth0] Failed to fetch JWKS: {exc}")
            return None

    @classmethod
    def _invalidate_cache(cls, domain: str) -> None:
        """
        Remove cached JWKS for a domain.
        Called when a token's key ID (kid) is not found in the cache,
        which means Auth0 has rotated its signing keys.
        """
        cls._jwks_cache.pop(domain, None)
        logger.info(f"[Auth0] JWKS cache invalidated for {domain}")

    @classmethod
    def verify(cls, token: str) -> dict | None:
        """
        Verify an Auth0 JWT access token.

        Returns the decoded payload dict on success, None on any failure.
        Never raises — all exceptions are caught and logged.

        Payload contains:
          sub       — Auth0 user ID  e.g. "auth0|64f3c2..."
          email     — user's email (if profile scope was requested)
          email_verified — bool
          nickname  — username suggestion
          iat       — issued at (Unix timestamp)
          exp       — expiry (Unix timestamp)
          aud       — audience (must match AUTH0_AUDIENCE in config)
          iss       — issuer (must match https://{AUTH0_DOMAIN}/)

        STRIDE Spoofing:
          - Signature verified against Auth0's public keys
          - Expiry (exp) checked — expired tokens rejected
          - Audience (aud) checked — tokens for other apps rejected
          - Issuer (iss) checked — tokens from other Auth0 tenants rejected
        """
        if not token:
            return None

        domain   = current_app.config.get("AUTH0_DOMAIN")
        audience = current_app.config.get("AUTH0_AUDIENCE")

        if not domain or not audience:
            logger.error("[Auth0] AUTH0_DOMAIN or AUTH0_AUDIENCE not configured.")
            return None

        jwks = cls._get_jwks(domain)
        if not jwks:
            return None

        try:
            # Decode header only (no verification) to get the key ID (kid)
            unverified_header = jwt.get_unverified_header(token)
        except JWTError as exc:
            logger.warning(f"[Auth0] Could not decode token header: {exc}")
            return None

        kid = unverified_header.get("kid")

        # Find the matching public key in JWKS by kid
        rsa_key = cls._find_rsa_key(jwks, kid)

        if not rsa_key:
            # Key not found — Auth0 may have rotated keys; invalidate cache and retry once
            logger.info("[Auth0] kid not found in cache — refreshing JWKS.")
            cls._invalidate_cache(domain)
            jwks = cls._get_jwks(domain)
            if jwks:
                rsa_key = cls._find_rsa_key(jwks, kid)

        if not rsa_key:
            logger.warning("[Auth0] No matching RSA key found for token.")
            return None

        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=["RS256"],       # Auth0 always uses RS256
                audience=audience,
                issuer=f"https://{domain}/",
            )
            return payload

        except ExpiredSignatureError:
            logger.warning("[Auth0] Token has expired.")
            return None
        except JWTError as exc:
            logger.warning(f"[Auth0] Token verification failed: {exc}")
            return None

    @staticmethod
    def _find_rsa_key(jwks: dict, kid: str) -> dict | None:
        """
        Extract the RSA public key matching the given key ID from JWKS.
        Returns a dict in the format python-jose expects, or None.
        """
        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                return {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n":   key["n"],
                    "e":   key["e"],
                }
        return None


# =============================================================================
# UserSyncService
# Syncs an Auth0 user into the MySQL database.
# =============================================================================

class UserSyncService:
    """
    Creates or updates a User row from Auth0 token claims.

    Called by routes.py after every successful token verification.
    This is how Auth0 users enter our MySQL database.

    STRIDE Tampering:
      Role is never taken from the token or request body.
      New users always get role='customer'.
      Role changes require a separate admin endpoint.

    STRIDE Repudiation:
      Every sync event is written to AuditLog with IP and user agent.
    """

    @staticmethod
    def sync(auth0_payload: dict) -> tuple["User | None", str | None]:
        """
        Find or create a User row from Auth0 token claims.

        Returns (user, None) on success.
        Returns (None, error_message) on failure.

        auth0_payload keys used:
          sub               — Auth0 unique user ID (required)
          email             — user's email address (required)
          email_verified    — bool (optional, defaults False)
          nickname          — suggested username (optional)
        """
        auth0_id = auth0_payload.get("sub")
        email    = auth0_payload.get("email")

        # Access tokens don't always include email — fetch from Auth0 userinfo if missing
        if not email and auth0_id:
            try:
                domain = current_app.config.get("AUTH0_DOMAIN")
                token  = flask_request.headers.get("Authorization", "").split(" ", 1)[-1]
                resp   = requests.get(
                    f"https://{domain}/userinfo",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=5,
                )
                if resp.ok:
                    userinfo = resp.json()
                    email = userinfo.get("email")
            except Exception as exc:
                logger.warning(f"[UserSync] Could not fetch userinfo: {exc}")

        if not auth0_id or not email:
            logger.warning("[UserSync] Token missing sub or email claim.")
            return None, "Invalid token claims."

        email = email.strip().lower()

        try:
            user = User.query.filter_by(auth0_id=auth0_id).first()

            if user:
                # Existing user — update fields that may have changed in Auth0
                if auth0_payload.get("email_verified") or auth0_id.startswith("google-oauth2|"):
                    user.is_verified = True
                user.last_login_at = datetime.now(timezone.utc)

                AuditLog.record(
                    event="LOGIN_AUTH0",
                    user_id=user.id,
                    ip_address=_get_ip(),
                    user_agent=_get_ua(),
                    detail=f"auth0_id={auth0_id}",
                )
                logger.info(f"[UserSync] Existing user logged in: {email}")

            else:
                # New user — create a row in MySQL for the first time
                username = _derive_username(auth0_payload, email)

                user = User(
                    auth0_id    = auth0_id,
                    email       = email,
                    username    = username,
                    role        = "customer",   # STRIDE Elevation: always customer
                    is_verified = auth0_payload.get("email_verified", False) or auth0_id.startswith("google-oauth2|"),
                    is_active   = True,
                )
                db.session.add(user)
                # Flush to get the user.id before AuditLog.record()
                db.session.flush()

                AuditLog.record(
                    event="REGISTRATION_AUTH0",
                    user_id=user.id,
                    ip_address=_get_ip(),
                    user_agent=_get_ua(),
                    detail=f"auth0_id={auth0_id}",
                )
                logger.info(f"[UserSync] New user registered: {email}")

            db.session.commit()
            return user, None

        except Exception as exc:
            db.session.rollback()
            logger.error(f"[UserSync] Database error during sync: {exc}")
            return None, "Failed to sync user. Please try again."


# =============================================================================
# Private helpers
# =============================================================================

def _get_ip() -> str:
    """
    Extract the real client IP from the request.
    Respects X-Forwarded-For when Flask is behind a reverse proxy (Nginx).

    STRIDE Info Disclosure: IP is stored in AuditLog for security purposes
    only — never returned in public API responses.
    """
    forwarded = flask_request.headers.get("X-Forwarded-For")
    if forwarded:
        # X-Forwarded-For can be a comma-separated list; first entry is client
        return forwarded.split(",")[0].strip()
    return flask_request.remote_addr or "unknown"


def _get_ua() -> str:
    """Return a truncated User-Agent string for audit logging."""
    return (flask_request.user_agent.string or "unknown")[:256]


def _derive_username(payload: dict, email: str) -> str:
    """
    Derive a safe username from the Auth0 token payload.
    Falls back to the email prefix if no nickname is available.
    Strips non-alphanumeric characters to prevent injection in display names.

    STRIDE Tampering: username is derived server-side from verified
    Auth0 claims — never taken raw from a request body.
    """
    import re
    raw = payload.get("nickname") or payload.get("name") or email.split("@")[0]
    # Keep only letters, numbers, underscores; truncate to 50 chars
    safe = re.sub(r"[^\w]", "_", raw)[:50]
    return safe or "user"
