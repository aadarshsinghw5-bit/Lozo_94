import os
import hashlib
import hmac
import secrets
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

GATEWAY_SECRET = os.getenv(
    "GATEWAY_SECRET",
    ""
).strip()

SESSION_MINUTES = 10


# ============================================================
# ERROR PAGE
# ============================================================

def error_page(
    message: str,
    status_code: int = 400
):
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
                    box-shadow:
                        0 10px 30px
                        rgba(0,0,0,0.25);
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
# SECRET
# ============================================================

def get_secret():

    if not GATEWAY_SECRET:
        raise RuntimeError(
            "GATEWAY_SECRET is missing in Vercel."
        )

    return GATEWAY_SECRET.encode(
        "utf-8"
    )


# ============================================================
# HMAC SIGNING
# ============================================================

def sign_value(value: str):

    signature = hmac.new(
        get_secret(),
        value.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    return f"{value}.{signature}"


def verify_signed_value(
    signed_value: str
):

    if not signed_value:
        return None

    try:

        value, signature = (
            signed_value.rsplit(
                ".",
                1
            )
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
# SESSION
# ============================================================

def create_session(
    token: str
):

    nonce = secrets.token_urlsafe(
        32
    )

    expiry = int(
        (
            datetime.now(timezone.utc)
            + timedelta(
                minutes=SESSION_MINUTES
            )
        ).timestamp()
    )

    raw = (
        f"{token}:"
        f"{nonce}:"
        f"{expiry}"
    )

    return sign_value(
        raw
    )


def validate_session(
    signed_session: str,
    token: str
):

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

        if not hmac.compare_digest(
            session_token,
            token
        ):
            return False

        now = int(
            datetime.now(
                timezone.utc
            ).timestamp()
        )

        if now >= expiry:
            return False

        return True

    except Exception:
        return False


# ============================================================
# SUPABASE TOKEN
# ============================================================

def get_token_row(
    token: str
):

    supabase = get_supabase()

    result = (
        supabase
        .table("tokens")
        .select(
            "token,user_id,target,"
            "expires_at,used"
        )
        .eq(
            "token",
            token
        )
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
        return (
            False,
            "❌ This link is invalid or expired."
        )

    # IMPORTANT:
    # Gateway DOES NOT change this value.
    #
    # The Telegram bot is responsible for
    # consuming the token.

    if row.get("used") is True:

        return (
            False,
            "❌ This link has already been used."
        )

    expires_at = row.get(
        "expires_at"
    )

    if not expires_at:

        return (
            False,
            "❌ This link has no expiry."
        )

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

        if (
            datetime.now(timezone.utc)
            >= expiry
        ):

            return (
                False,
                "❌ This link has expired."
            )

    except Exception:

        return (
            False,
            "❌ Invalid expiry information."
        )

    return (
        True,
        None
    )


# ============================================================
# TELEGRAM TARGET
# ============================================================

def get_target_url(
    row,
    token: str
):

    target = str(
        row.get("target") or ""
    ).strip()

    # Existing tokens normally contain the
    # Telegram target.
    if target:

        parsed = urlparse(
            target
        )

        allowed_hosts = {
            "t.me",
            "telegram.me",
            "www.t.me",
            "www.telegram.me"
        }

        if (
            parsed.scheme == "https"
            and parsed.netloc.lower()
            in allowed_hosts
        ):
            return target

    # Fallback for existing database rows
    return (
        f"https://t.me/"
        f"{BOT_USERNAME}"
        f"?start=verify_{token}"
    )


# ============================================================
# CREATE VP LINK
# ============================================================

def create_vplink(
    destination_url: str
):

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

    if data.get(
        "status"
    ) != "success":

        raise RuntimeError(
            data.get(
                "message",
                "VPLINK could not create the link."
            )
        )

    shortened_url = (
        data.get(
            "shortenedUrl"
        )
        or
        data.get(
            "shortened_url"
        )
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
# /api/gateway?token=XXXX
#
# Creates a signed browser session and
# sends the user to VP Links.
# ============================================================

@app.get("/api/gateway")
async def gateway(
    request: Request,
    token: str = Query(...)
):

    token = token.strip()

    # --------------------------------------------------------
    # Basic validation
    # --------------------------------------------------------

    if (
        not token
        or len(token) < 10
    ):

        return error_page(
            "❌ Invalid link."
        )

    # --------------------------------------------------------
    # Configuration
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
        # Database token
        # ----------------------------------------------------

        row = get_token_row(
            token
        )

        valid, message = (
            validate_token(
                row
            )
        )

        if not valid:

            return error_page(
                message
            )

        # ----------------------------------------------------
        # Session
        # ----------------------------------------------------

        session = create_session(
            token
        )

        # ----------------------------------------------------
        # Protected return URL
        #
        # IMPORTANT:
        # VP Links gets /api/complete,
        # NOT the Telegram deep link.
        # ----------------------------------------------------

        hostname = (
            request.url.hostname
            or ""
        )

        complete_url = (
            f"https://{hostname}"
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
        # Redirect to VP Links
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
# VP LINKS RETURN
#
# /api/complete?token=XXXX
#
# IMPORTANT:
# This endpoint NEVER sets tokens.used=True.
#
# The Telegram bot does that when it receives:
#
# /start verify_TOKEN
#
# ============================================================

@app.get("/api/complete")
async def complete(
    request: Request,
    token: str = Query(...)
):

    token = token.strip()

    if (
        not token
        or len(token) < 10
    ):

        return error_page(
            "❌ Invalid link."
        )

    if not GATEWAY_SECRET:

        return error_page(
            "⚠️ GATEWAY_SECRET is missing in Vercel."
        )

    try:

        # ----------------------------------------------------
        # Token check
        # ----------------------------------------------------

        row = get_token_row(
            token
        )

        valid, message = (
            validate_token(
                row
            )
        )

        if not valid:

            return error_page(
                message
            )

        # ----------------------------------------------------
        # Check browser session
        # ----------------------------------------------------

        session = request.cookies.get(
            "gateway_session"
        )

        if not validate_session(
            session,
            token
        ):

            # ------------------------------------------------
            # No valid session.
            #
            # Do NOT expose Telegram target.
            #
            # Start a fresh VP cycle.
            # ------------------------------------------------

            new_session = create_session(
                token
            )

            hostname = (
                request.url.hostname
                or ""
            )

            retry_url = (
                f"https://{hostname}"
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
        # Valid gateway session
        # ----------------------------------------------------

        target = get_target_url(
            row,
            token
        )

        # ----------------------------------------------------
        # IMPORTANT:
        #
        # DO NOT update tokens.used here.
        #
        # Telegram bot must consume the token.
        # ----------------------------------------------------

        response = RedirectResponse(
            url=target,
            status_code=302
        )

        # Remove session after successful handoff
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
