import os
import hmac
import hashlib
import secrets
from datetime import datetime, timezone, timedelta

import requests
from fastapi import FastAPI, Query, Request
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi import Response
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


# ============================================================
# SETTINGS
# ============================================================

SESSION_MINUTES = 10

SESSION_COOKIE = "gateway_session"

# Random extra salt used for signing
SIGN_VERSION = "v2"


# ============================================================
# ERROR PAGE
# ============================================================

def error_page(message: str, status_code: int = 400):
    return HTMLResponse(
        content=f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta
                name="viewport"
                content="width=device-width, initial-scale=1"
            >

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
# BASIC CONFIG CHECK
# ============================================================

def config_ok():
    return (
        bool(SUPABASE_URL)
        and bool(SUPABASE_SERVICE_ROLE_KEY)
        and bool(BOT_USERNAME)
        and bool(VPLINK_API_KEY)
        and bool(GATEWAY_SECRET)
    )


# ============================================================
# SIGNING
# ============================================================

def sign_value(value: str) -> str:
    return hmac.new(
        GATEWAY_SECRET.encode(),
        value.encode(),
        hashlib.sha256
    ).hexdigest()


def make_session(token: str, nonce: str, expires: int) -> str:
    payload = (
        f"{SIGN_VERSION}|"
        f"{token}|"
        f"{nonce}|"
        f"{expires}"
    )

    signature = sign_value(payload)

    return (
        f"{SIGN_VERSION}."
        f"{token}."
        f"{nonce}."
        f"{expires}."
        f"{signature}"
    )


def verify_session(
    session: str,
    token: str
):
    try:
        parts = session.split(".")

        if len(parts) != 5:
            return None

        version = parts[0]
        session_token = parts[1]
        nonce = parts[2]
        expires_text = parts[3]
        signature = parts[4]

        if version != SIGN_VERSION:
            return None

        if not hmac.compare_digest(
            session_token,
            token
        ):
            return None

        expires = int(expires_text)

        now = int(
            datetime.now(
                timezone.utc
            ).timestamp()
        )

        if now >= expires:
            return None

        payload = (
            f"{version}|"
            f"{session_token}|"
            f"{nonce}|"
            f"{expires}"
        )

        expected = sign_value(payload)

        if not hmac.compare_digest(
            signature,
            expected
        ):
            return None

        return {
            "token": session_token,
            "nonce": nonce,
            "expires": expires
        }

    except Exception:
        return None


# ============================================================
# SUPABASE TOKEN
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

def validate_token(token: str):
    if not token:
        return None, "invalid"

    if len(token) < 10:
        return None, "invalid"

    try:
        row = get_token_row(token)

        if not row:
            return None, "invalid"

        if row.get("used") is True:
            return None, "used"

        expires_at = row.get("expires_at")

        if not expires_at:
            return None, "expired"

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

        except Exception:
            return None, "expired"

        if datetime.now(
            timezone.utc
        ) >= expiry:
            return None, "expired"

        return row, "ok"

    except Exception as error:
        print(
            "TOKEN VALIDATION ERROR:",
            repr(error)
        )

        return None, "error"


# ============================================================
# TELEGRAM TARGET
# ============================================================

def get_target_url(row, token: str):
    target = str(
        row.get("target") or ""
    ).strip()

    # If target is a valid Telegram HTTPS URL,
    # use it.
    if target.startswith(
        "https://t.me/"
    ):
        return target

    if target.startswith(
        "https://telegram.me/"
    ):
        return target

    # Fallback to bot verification URL.
    return (
        f"https://t.me/"
        f"{BOT_USERNAME}"
        f"?start=verify_{token}"
    )


# ============================================================
# VP LINKS
# ============================================================

def create_vplink(destination: str):
    if not VPLINK_API_KEY:
        raise RuntimeError(
            "VPLINK API key is missing"
        )

    response = requests.get(
        VPLINK_API_URL,
        params={
            "api": VPLINK_API_KEY,
            "url": destination
        },
        timeout=20
    )

    response.raise_for_status()

    try:
        data = response.json()

    except Exception:
        raise RuntimeError(
            "VPLINK returned invalid JSON"
        )

    if data.get("status") != "success":
        raise RuntimeError(
            data.get(
                "message",
                "VPLINK could not create link."
            )
        )

    shortened_url = (
        data.get("shortenedUrl")
        or data.get("shortened_url")
    )

    if not shortened_url:
        raise RuntimeError(
            "VPLINK shortened URL missing"
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
# ============================================================

@app.get("/api/gateway")
async def gateway(
    token: str = Query(...),
    response: Response = None
):
    token = token.strip()

    # --------------------------------------------------------
    # CONFIG CHECK
    # --------------------------------------------------------

    if not config_ok():
        return error_page(
            "⚠️ Gateway configuration is incomplete.",
            500
        )

    # --------------------------------------------------------
    # TOKEN CHECK
    # --------------------------------------------------------

    row, status = validate_token(token)

    if status == "used":
        return error_page(
            "❌ This link has already been used."
        )

    if status == "expired":
        return error_page(
            "❌ This link has expired."
        )

    if status != "ok":
        return error_page(
            "❌ This link is invalid."
        )

    # --------------------------------------------------------
    # CREATE ONE-TIME SESSION
    # --------------------------------------------------------

    nonce = secrets.token_urlsafe(24)

    expires = int(
        (
            datetime.now(timezone.utc)
            + timedelta(
                minutes=SESSION_MINUTES
            )
        ).timestamp()
    )

    session = make_session(
        token,
        nonce,
        expires
    )

    # --------------------------------------------------------
    # IMPORTANT
    #
    # VP Links destination is NOT Telegram.
    #
    # It goes to /api/complete.
    # --------------------------------------------------------

    complete_url = (
        f"https://"
        f"{os.getenv('VERCEL_URL', '').strip()}"
        f"/api/complete"
        f"?token={token}"
    )

    # VERCEL_URL may not exist in some deployments.
    # Use fixed production hostname as fallback.

    if (
        not os.getenv(
            "VERCEL_URL",
            ""
        ).strip()
    ):
        complete_url = (
            "https://lozo-94.vercel.app"
            "/api/complete"
            f"?token={token}"
        )

    try:
        shortened_url = create_vplink(
            complete_url
        )

    except requests.RequestException as error:
        print(
            "VPLINK REQUEST ERROR:",
            repr(error)
        )

        return error_page(
            "⚠️ VPLINK request failed.",
            502
        )

    except Exception as error:
        print(
            "VPLINK ERROR:",
            repr(error)
        )

        return error_page(
            "⚠️ Could not create short link.",
            502
        )

    # --------------------------------------------------------
    # REDIRECT TO VP LINKS
    # --------------------------------------------------------

    redirect = RedirectResponse(
        url=shortened_url,
        status_code=302
    )

    redirect.set_cookie(
        key=SESSION_COOKIE,
        value=session,
        max_age=SESSION_MINUTES * 60,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/"
    )

    return redirect


# ============================================================
# COMPLETE
# ============================================================

@app.get("/api/complete")
async def complete(
    request: Request,
    token: str = Query(...)
):
    token = token.strip()

    # --------------------------------------------------------
    # CONFIG
    # --------------------------------------------------------

    if not config_ok():
        return error_page(
            "⚠️ Gateway configuration is incomplete.",
            500
        )

    # --------------------------------------------------------
    # TOKEN CHECK
    # --------------------------------------------------------

    row, status = validate_token(token)

    if status == "used":
        return error_page(
            "❌ This link has already been used."
        )

    if status == "expired":
        return error_page(
            "❌ This link has expired."
        )

    if status != "ok":
        return error_page(
            "❌ This link is invalid."
        )

    # --------------------------------------------------------
    # READ SESSION COOKIE
    # --------------------------------------------------------

    session = request.cookies.get(
        SESSION_COOKIE
    )

    verified_session = None

    if session:
        verified_session = verify_session(
            session,
            token
        )

    # --------------------------------------------------------
    # NO VALID SESSION
    #
    # Direct access / bypassed gateway URL:
    # create another VP cycle instead of
    # exposing Telegram.
    # --------------------------------------------------------

    if not verified_session:

        nonce = secrets.token_urlsafe(24)

        expires = int(
            (
                datetime.now(timezone.utc)
                + timedelta(
                    minutes=SESSION_MINUTES
                )
            ).timestamp()
        )

        new_session = make_session(
            token,
            nonce,
            expires
        )

        complete_url = (
            f"https://"
            f"{os.getenv('VERCEL_URL', '').strip()}"
            f"/api/complete"
            f"?token={token}"
        )

        if not os.getenv(
            "VERCEL_URL",
            ""
        ).strip():
            complete_url = (
                "https://lozo-94.vercel.app"
                "/api/complete"
                f"?token={token}"
            )

        try:
            shortened_url = create_vplink(
                complete_url
            )

        except requests.RequestException as error:
            print(
                "VPLINK REQUEST ERROR:",
                repr(error)
            )

            return error_page(
                "⚠️ VPLINK request failed.",
                502
            )

        except Exception as error:
            print(
                "VPLINK ERROR:",
                repr(error)
            )

            return error_page(
                "⚠️ Could not create short link.",
                502
            )

        redirect = RedirectResponse(
            url=shortened_url,
            status_code=302
        )

        redirect.set_cookie(
            key=SESSION_COOKIE,
            value=new_session,
            max_age=SESSION_MINUTES * 60,
            httponly=True,
            secure=True,
            samesite="lax",
            path="/"
        )

        return redirect

    # --------------------------------------------------------
    # VALID SESSION
    #
    # Do NOT mark token used here.
    # The Telegram bot does that after
    # verify_TOKEN is actually processed.
    # --------------------------------------------------------

    telegram_url = get_target_url(
        row,
        token
    )

    redirect = RedirectResponse(
        url=telegram_url,
        status_code=302
    )

    # Delete session immediately after use.
    redirect.delete_cookie(
        key=SESSION_COOKIE,
        path="/"
    )

    return redirect
