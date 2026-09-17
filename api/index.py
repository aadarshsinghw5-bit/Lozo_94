import os
import secrets
from datetime import datetime, timezone, timedelta
from urllib.parse import urlencode

import requests
from fastapi import FastAPI, Query
from fastapi.responses import RedirectResponse, HTMLResponse
from supabase import create_client


app = FastAPI()


# ============================================================
# ENV
# ============================================================

SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_SERVICE_ROLE_KEY = os.getenv(
    "SUPABASE_SERVICE_ROLE_KEY", ""
).strip()

BOT_USERNAME = os.getenv(
    "BOT_USERNAME", ""
).strip().lstrip("@")

VPLINK_API_URL = os.getenv(
    "VPLINK_API_URL",
    "https://vplink.in/api"
).strip()

VPLINK_API_KEY = os.getenv(
    "VPLINK_API_KEY", ""
).strip()

GATEWAY_DOMAIN = os.getenv(
    "GATEWAY_DOMAIN",
    "https://lozo-94.vercel.app"
).strip().rstrip("/")


# State lifetime
STATE_MINUTES = 10


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
                        0 10px 30px rgba(0,0,0,.25);
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
# CONFIG
# ============================================================

def config_ok():

    return (
        bool(SUPABASE_URL)
        and bool(SUPABASE_SERVICE_ROLE_KEY)
        and bool(BOT_USERNAME)
        and bool(VPLINK_API_KEY)
    )


# ============================================================
# ORIGINAL TOKEN
# ============================================================

def get_token(token: str):

    if not token:
        return None

    if len(token) < 10:
        return None

    try:

        db = get_supabase()

        result = (
            db
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

        row = rows[0]

        if row.get("used") is True:
            return None

        expires_at = row.get("expires_at")

        if not expires_at:
            return None

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

        if datetime.now(
            timezone.utc
        ) >= expiry:
            return None

        return row

    except Exception as e:

        print(
            "TOKEN ERROR:",
            repr(e)
        )

        return None


# ============================================================
# TARGET
# ============================================================

def telegram_target(row, token):

    target = str(
        row.get("target") or ""
    ).strip()

    if target.startswith(
        "https://t.me/"
    ):
        return target

    if target.startswith(
        "https://telegram.me/"
    ):
        return target

    return (
        f"https://t.me/"
        f"{BOT_USERNAME}"
        f"?start=verify_{token}"
    )


# ============================================================
# VP LINK
# ============================================================

def make_vplink(destination):

    response = requests.get(
        VPLINK_API_URL,
        params={
            "api": VPLINK_API_KEY,
            "url": destination
        },
        timeout=20
    )

    response.raise_for_status()

    data = response.json()

    if data.get("status") != "success":

        raise RuntimeError(
            data.get(
                "message",
                "VPLINK error"
            )
        )

    url = (
        data.get("shortenedUrl")
        or data.get("shortened_url")
    )

    if not url:
        raise RuntimeError(
            "No shortened URL returned"
        )

    return url


# ============================================================
# CREATE STATE
# ============================================================

def create_state(token):

    state = secrets.token_urlsafe(32)

    expires = (
        datetime.now(timezone.utc)
        + timedelta(
            minutes=STATE_MINUTES
        )
    ).isoformat()

    db = get_supabase()

    # gateway_states table required
    db.table(
        "gateway_states"
    ).insert({
        "state": state,
        "token": token,
        "expires_at": expires,
        "used": False
    }).execute()

    return state


# ============================================================
# GET STATE
# ============================================================

def get_state(state):

    if not state:
        return None

    try:

        db = get_supabase()

        result = (
            db
            .table("gateway_states")
            .select(
                "state,token,expires_at,used"
            )
            .eq(
                "state",
                state
            )
            .limit(1)
            .execute()
        )

        rows = result.data or []

        if not rows:
            return None

        row = rows[0]

        if row.get("used") is True:
            return None

        expires_at = row.get(
            "expires_at"
        )

        if not expires_at:
            return None

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

        if datetime.now(
            timezone.utc
        ) >= expiry:
            return None

        return row

    except Exception as e:

        print(
            "STATE ERROR:",
            repr(e)
        )

        return None


# ============================================================
# CONSUME STATE
# ============================================================

def consume_state(state):

    try:

        db = get_supabase()

        db.table(
            "gateway_states"
        ).update({
            "used": True
        }).eq(
            "state",
            state
        ).execute()

        return True

    except Exception as e:

        print(
            "STATE CONSUME ERROR:",
            repr(e)
        )

        return False


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
# GATEWAY
# ============================================================

@app.get("/api/gateway")
async def gateway(
    token: str = Query(default="")
):

    token = token.strip()

    if not token:
        return error_page(
            "❌ Invalid or incomplete link."
        )

    if not config_ok():
        return error_page(
            "⚠️ Gateway configuration is incomplete.",
            500
        )

    row = get_token(token)

    if not row:
        return error_page(
            "❌ This link is invalid, expired or already used."
        )

    try:

        # Create random state.
        state = create_state(token)

        # VP destination contains ONLY opaque state.
        destination = (
            f"{GATEWAY_DOMAIN}"
            f"/api/complete?"
            f"{urlencode({'state': state})}"
        )

        short_url = make_vplink(
            destination
        )

        return RedirectResponse(
            url=short_url,
            status_code=302
        )

    except requests.RequestException as e:

        print(
            "VPLINK REQUEST ERROR:",
            repr(e)
        )

        return error_page(
            "⚠️ VPLINK request failed.",
            502
        )

    except Exception as e:

        print(
            "GATEWAY ERROR:",
            repr(e)
        )

        return error_page(
            "⚠️ Gateway error. Please try again.",
            500
        )


# ============================================================
# COMPLETE
# ============================================================

@app.get("/api/complete")
async def complete(
    state: str = Query(default="")
):

    state = state.strip()

    # --------------------------------------------------------
    # No state
    # --------------------------------------------------------

    if not state:

        return error_page(
            "❌ Invalid or incomplete link."
        )

    if not config_ok():

        return error_page(
            "⚠️ Gateway configuration is incomplete.",
            500
        )

    # --------------------------------------------------------
    # Validate state
    # --------------------------------------------------------

    state_row = get_state(state)

    if not state_row:

        return error_page(
            "❌ This verification session is invalid or expired."
        )

    token = str(
        state_row.get("token") or ""
    ).strip()

    if not token:

        return error_page(
            "❌ Invalid verification session."
        )

    # --------------------------------------------------------
    # Validate original token again
    # --------------------------------------------------------

    row = get_token(token)

    if not row:

        return error_page(
            "❌ This link is invalid, expired or already used."
        )

    # --------------------------------------------------------
    # IMPORTANT
    #
    # State is consumed before Telegram redirect.
    # --------------------------------------------------------

    consume_state(state)

    telegram_url = telegram_target(
        row,
        token
    )

    return RedirectResponse(
        url=telegram_url,
        status_code=302
    )
