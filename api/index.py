import os
import secrets
import hashlib
import hmac
from datetime import datetime, timezone, timedelta
from urllib.parse import urlencode, urlparse

import requests
from fastapi import FastAPI, Query, Request
from fastapi.responses import RedirectResponse, HTMLResponse
from supabase import create_client


app = FastAPI()


# ============================================================
# ENVIRONMENT VARIABLES
# ============================================================

SUPABASE_URL = os.getenv(
    "SUPABASE_URL",
    ""
).strip()

SUPABASE_SERVICE_ROLE_KEY = os.getenv(
    "SUPABASE_SERVICE_ROLE_KEY",
    ""
).strip()

BOT_USERNAME = os.getenv(
    "BOT_USERNAME",
    ""
).strip().lstrip("@")

VPLINK_API_URL = os.getenv(
    "VPLINK_API_URL",
    "https://vplink.in/api"
).strip()

VPLINK_API_KEY = os.getenv(
    "VPLINK_API_KEY",
    ""
).strip()

# IMPORTANT:
# Add a long random value in Vercel Environment Variables.
#
# Example:
# GATEWAY_SECRET = a-long-random-secret-value
#
GATEWAY_SECRET = os.getenv(
    "GATEWAY_SECRET",
    ""
).strip()

# How long a gateway session remains valid
SESSION_MINUTES = 10


# ============================================================
# ERROR PAGE
# ============================================================

def error_page(message: str, status_code: int = 400):
    return HTMLResponse(
        content=f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta name="viewport"
                  content="width=device-width, initial-scale=1">
            <title>Link Error</title>

            <style>
                body {{
                    margin: 0;
                    padding: 50px 18px;
                    background: #111827;
                    color: white;
                    font-family: Arial, sans-serif;
                    text-align: center;
                }}

                .box {{
                    max-width: 420px;
                    margin: auto;
                    padding: 30px 22px;
                    border-radius: 18px;
                    background: #1f2937;
                    box-shadow: 0 10px 30px rgba(0,0,0,0.25);
                }}

                h2 {{
                    margin: 0;
                    font-size: 21px;
                }}
            </style>
        </head>

        <body>
            <div class="box">
                <h2>{message}</h2>
            </div>
        </body>
        </html>
        """,
        status_code=status_code
    )


# ============================================================
# SUPABASE
# ============================================================

def get_supabase():
    if not SUPABASE_URL:
        raise RuntimeError(
            "SUPABASE_URL is missing"
        )

    if not SUPABASE_SERVICE_ROLE_KEY:
        raise RuntimeError(
            "SUPABASE_SERVICE_ROLE_KEY is missing"
        )

    return create_client(
        SUPABASE_URL,
        SUPABASE_SERVICE_ROLE_KEY
    )


# ============================================================
# SECRET / SIGNING HELPERS
# ============================================================

def get_secret() -> bytes:
    if not GATEWAY_SECRET:
        raise RuntimeError(
            "GATEWAY_SECRET is missing in Vercel."
        )

    return GATEWAY_SECRET.encode("utf-8")


def sign_value(value: str) -> str:
    secret = get_secret()

    signature = hmac.new(
        secret,
        value.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    return f"{value}.{signature}"


def verify_signed_value(signed_value: str):
    if not signed_value:
        return None

    try:
        value, signature = signed_value.rsplit(
            ".",
            1
        )

        expected = hmac.new(
            get_secret(),
            value.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(
            signature,
            expected
        ):
            return None

        return value

    except Exception:
        return None


# ============================================================
# SESSION COOKIE
# ============================================================

def create_session(token: str) -> str:
    """
    Creates a random, signed session.

    Format before signing:
        token:nonce:expiry_timestamp
    """

    nonce = secrets.token_urlsafe(32)

    expiry = int(
        (
            datetime.now(timezone.utc)
            + timedelta(minutes=SESSION_MINUTES)
        ).timestamp()
    )

    raw = f"{token}:{nonce}:{expiry}"

    return sign_value(raw)


def validate_session(
    signed_session: str,
    token: str
) -> bool:

    raw = verify_signed_value(
        signed_session
    )

    if not raw:
        return False

    try:
        parts = raw.split(":")

        if len(parts) != 3:
            return False

        session_token = parts[0]
        expiry = int(parts[2])

        # Session must belong to this token
        if not hmac.compare_digest(
            session_token,
            token
        ):
            return False

        # Session expiry
        if int(
            datetime.now(timezone.utc).timestamp()
        ) >= expiry:
            return False

        return True

    except Exception:
        return False


# ============================================================
# TOKEN LOOKUP
# ============================================================

def get_token_row(token: str):
    supabase = get_supabase()

    result = (
        supabase
        .table("tokens")
        .select(
            "token,user_id,target,expires_at,used"
        )
        .eq("token", token)
        .limit(1)
        .execute()
    )

    rows = result.data or []

    if not rows:
        return None

    return rows[0]


# ============================================================
# TOKEN VALIDATION
# ============================================================

def validate_token(row):
    if not row:
        return False, "❌ This link is invalid or expired."

    # One-time use
    if row.get("used") is True:
        return False, "❌ This link has already been used."

    expires_at = row.get("expires_at")

    if not expires_at:
        return False, "❌ This link has no expiry."

    try:
        expiry = datetime.fromisoformat(
            str(expires_at).replace(
                "Z",
                "+00:00"
            )
        )

        if expiry.tzinfo is None:
            expiry = expiry.replace(
                tzinfo=timezone.utc
            )

        if datetime.now(timezone.utc) >= expiry:
            return False, "❌ This link has expired."

    except Exception:
        return False, "❌ Invalid expiry information."

    return True, None


# ============================================================
# TARGET VALIDATION
# ============================================================

def get_target_url(row):
    target = str(
        row.get("target") or ""
    ).strip()

    if not target:
        return None

    parsed = urlparse(target)

    # Only HTTPS destinations
    if parsed.scheme != "https":
        return None

    # Telegram target
    if parsed.netloc.lower() not in {
        "t.me",
        "telegram.me",
        "www.t.me",
        "www.telegram.me"
    }:
        return None

    return target


# ============================================================
# CREATE VP LINK
# ============================================================

def create_vplink(destination_url: str):
    response = requests.get(
        VPLINK_API_URL,
        params={
            "api": VPLINK_API_KEY,
            "url": destination_url
        },
        timeout=20
    )

    response.raise_for_status()

    try:
        data = response.json()

    except Exception:
        raise RuntimeError(
            "VPLINK returned an invalid response."
        )

    if data.get("status") != "success":
        raise RuntimeError(
            data.get(
                "message",
                "VPLINK could not create the link."
            )
        )

    shortened_url = (
        data.get("shortenedUrl")
        or data.get("shortened_url")
    )

    if not shortened_url:
        raise RuntimeError(
            "VPLINK link was not received."
        )

    return shortened_url


# ============================================================
# HOME
# ============================================================

@app.get("/")
async def home():
    return {
        "status": "ok",
        "service": "lozo-94-gateway"
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
async def health():
    return {
        "status": "ok"
    }


# ============================================================
# MAIN GATEWAY
#
# User enters:
#
# /api/gateway?token=XXXX
#
# Gateway creates a private session cookie and sends the user
# through VP Links.
# ============================================================

@app.get("/api/gateway")
async def gateway(
    request: Request,
    token: str = Query(...)
):

    token = token.strip()

    # --------------------------------------------------------
    # Basic token validation
    # --------------------------------------------------------

    if not token or len(token) < 10:
        return error_page(
            "❌ Invalid link."
        )

    # --------------------------------------------------------
    # Required configuration
    # --------------------------------------------------------

    if not BOT_USERNAME:
        return error_page(
            "⚠️ BOT_USERNAME is missing in Vercel."
        )

    if not VPLINK_API_KEY:
        return error_page(
            "⚠️ VPLINK API key is missing in Vercel."
        )

    if not GATEWAY_SECRET:
        return error_page(
            "⚠️ GATEWAY_SECRET is missing in Vercel."
        )

    try:

        # ----------------------------------------------------
        # Get token from Supabase
        # ----------------------------------------------------

        row = get_token_row(token)

        valid, message = validate_token(row)

        if not valid:
            return error_page(
                message
            )

        # ----------------------------------------------------
        # Get the actual Telegram destination
        # ----------------------------------------------------

        target = get_target_url(row)

        if not target:

            # Fallback for existing records where target
            # may not have been populated correctly.
            target = (
                f"https://t.me/{BOT_USERNAME}"
                f"?start=verify_{token}"
            )

        # ----------------------------------------------------
        # Create private gateway session
        # ----------------------------------------------------

        session = create_session(token)

        # ----------------------------------------------------
        # VP Links must point BACK to this gateway.
        #
        # The original Telegram target is NOT sent to VP Links.
        # ----------------------------------------------------

        complete_url = (
            f"https://{request.url.hostname}"
            f"/api/complete?"
            f"{urlencode({'token': token})}"
        )

        # ----------------------------------------------------
        # Create VP Link
        # ----------------------------------------------------

        shortened_url = create_vplink(
            complete_url
        )

        # ----------------------------------------------------
        # Redirect user to VP Links.
        #
        # Cookie is set BEFORE redirect.
        # ----------------------------------------------------

        response = RedirectResponse(
            url=shortened_url,
            status_code=302
        )

        response.set_cookie(
            key="gateway_session",
            value=session,
            max_age=SESSION_MINUTES * 60,
            httponly=True,
            secure=True,
            samesite="lax",
            path="/"
        )

        return response

    except requests.RequestException as error:

        print(
            "VPLINK REQUEST ERROR:",
            repr(error)
        )

        return error_page(
            "⚠️ VPLINK request failed.",
            status_code=502
        )

    except Exception as error:

        print(
            "GATEWAY ERROR:",
            repr(error)
        )

        return error_page(
            "⚠️ Gateway error. Please try again later.",
            status_code=500
        )


# ============================================================
# VP LINKS RETURN / COMPLETE
#
# This is the important protection layer.
#
# VP Links should redirect here after completion.
#
# A bypasser may know this URL, BUT:
#
#   /api/complete?token=XXXX
#
# without the private gateway_session cookie
# will NOT unlock the Telegram target.
# ============================================================

@app.get("/api/complete")
async def complete(
    request: Request,
    token: str = Query(...)
):

    token = token.strip()

    if not token or len(token) < 10:
        return error_page(
            "❌ Invalid link."
        )

    if not GATEWAY_SECRET:
        return error_page(
            "⚠️ GATEWAY_SECRET is missing in Vercel."
        )

    try:

        # ----------------------------------------------------
        # Get token
        # ----------------------------------------------------

        row = get_token_row(token)

        valid, message = validate_token(row)

        if not valid:
            return error_page(
                message
            )

        # ----------------------------------------------------
        # Check private session cookie
        # ----------------------------------------------------

        session = request.cookies.get(
            "gateway_session"
        )

        session_valid = validate_session(
            session,
            token
        )

        # ----------------------------------------------------
        # NO VALID SESSION
        #
        # This is what catches a direct/bypassed gateway URL.
        #
        # Instead of giving the Telegram URL,
        # send the user through a fresh VP Link.
        # ----------------------------------------------------

        if not session_valid:

            new_session = create_session(
                token
            )

            retry_url = (
                f"https://{request.url.hostname}"
                f"/api/complete?"
                f"{urlencode({'token': token})}"
            )

            shortened_url = create_vplink(
                retry_url
            )

            response = RedirectResponse(
                url=shortened_url,
                status_code=302
            )

            response.set_cookie(
                key="gateway_session",
                value=new_session,
                max_age=SESSION_MINUTES * 60,
                httponly=True,
                secure=True,
                samesite="lax",
                path="/"
            )

            return response

        # ----------------------------------------------------
        # VALID SESSION
        # ----------------------------------------------------

        target = get_target_url(row)

        if not target:
            target = (
                f"https://t.me/{BOT_USERNAME}"
                f"?start=verify_{token}"
            )

        # ----------------------------------------------------
        # Mark token as used BEFORE redirect.
        #
        # This makes the gateway one-time.
        # ----------------------------------------------------

        supabase = get_supabase()

        (
            supabase
            .table("tokens")
            .update({
                "used": True
            })
            .eq("token", token)
            .eq("used", False)
            .execute()
        )

        # ----------------------------------------------------
        # Delete gateway cookie
        # ----------------------------------------------------

        response = RedirectResponse(
            url=target,
            status_code=302
        )

        response.delete_cookie(
            key="gateway_session",
            path="/"
        )

        return response

    except requests.RequestException as error:

        print(
            "VPLINK REQUEST ERROR:",
            repr(error)
        )

        return error_page(
            "⚠️ VPLINK request failed.",
            status_code=502
        )

    except Exception as error:

        print(
            "COMPLETE ERROR:",
            repr(error)
        )

        return error_page(
            "⚠️ Gateway error. Please try again later.",
            status_code=500
        )
