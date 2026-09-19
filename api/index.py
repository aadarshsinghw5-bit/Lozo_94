import os
import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from urllib.parse import urlencode

import requests
from fastapi import FastAPI, Request, Query
from fastapi.responses import HTMLResponse, RedirectResponse
from supabase import create_client


app = FastAPI(title="Lozo Gateway")


# =========================================================
# ENVIRONMENT
# =========================================================

SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_SERVICE_ROLE_KEY = os.getenv(
    "SUPABASE_SERVICE_ROLE_KEY", ""
).strip()

BOT_USERNAME = os.getenv(
    "BOT_USERNAME", ""
).strip().lstrip("@")

VPLINK_API_URL = os.getenv(
    "VPLINK_API_URL",
    "https://vplink.in/api",
).strip().rstrip("/")

VPLINK_API_KEY = os.getenv(
    "VPLINK_API_KEY",
    "",
).strip()

GATEWAY_DOMAIN = os.getenv(
    "GATEWAY_DOMAIN",
    "https://lozo-94.vercel.app",
).strip().rstrip("/")


# =========================================================
# SETTINGS
# =========================================================

STATE_TTL_MINUTES = 30
VERIFY_TTL_MINUTES = 10

BROWSER_COOKIE = "lozo_browser_id"
VERIFIED_COOKIE = "lozo_verified"


# =========================================================
# SUPABASE
# =========================================================

supabase = None

if SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY:
    supabase = create_client(
        SUPABASE_URL,
        SUPABASE_SERVICE_ROLE_KEY,
    )


# =========================================================
# TIME HELPERS
# =========================================================

def now_utc():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.astimezone(timezone.utc).isoformat()


def parse_datetime(value):
    if not value:
        return None

    try:
        return datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )
    except Exception:
        return None


# =========================================================
# SECURITY HELPERS
# =========================================================

def generate_browser_id():
    return secrets.token_urlsafe(32)


def generate_state():
    return secrets.token_urlsafe(32)


def hash_browser(browser_id):
    return hashlib.sha256(
        browser_id.encode("utf-8")
    ).hexdigest()


def get_browser_id(request: Request):
    return request.cookies.get(BROWSER_COOKIE)


def get_or_create_browser_id(request: Request):
    browser_id = get_browser_id(request)

    if browser_id:
        return browser_id, False

    return generate_browser_id(), True


# =========================================================
# TELEGRAM
# =========================================================

def create_telegram_link(token):
    if not BOT_USERNAME:
        return None

    return (
        f"https://t.me/{BOT_USERNAME}"
        f"?{urlencode({'start': token})}"
    )


# =========================================================
# DATABASE
# =========================================================

def require_database():
    if supabase is None:
        raise RuntimeError(
            "Supabase is not configured."
        )


def get_token(token):
    require_database()

    result = (
        supabase
        .table("tokens")
        .select("*")
        .eq("token", token)
        .limit(1)
        .execute()
    )

    if not result.data:
        return None

    return result.data[0]


def get_gateway_state(state):
    require_database()

    result = (
        supabase
        .table("gateway_states")
        .select("*")
        .eq("state", state)
        .limit(1)
        .execute()
    )

    if not result.data:
        return None

    return result.data[0]


def create_gateway_state(token, browser_id):
    require_database()

    state = generate_state()

    expires_at = (
        now_utc()
        + timedelta(minutes=STATE_TTL_MINUTES)
    )

    row = {
        "state": state,
        "token": token,
        "expires_at": iso(expires_at),
        "used": False,
        "verified": False,
        "browser_hash": hash_browser(browser_id),
    }

    supabase.table(
        "gateway_states"
    ).insert(row).execute()

    return state


def update_gateway_state(state, values):
    require_database()

    return (
        supabase
        .table("gateway_states")
        .update(values)
        .eq("state", state)
        .execute()
    )


# =========================================================
# VPLINK
# =========================================================

def create_vplink(target_url):
    if not VPLINK_API_KEY:
        raise RuntimeError(
            "VPLINK_API_KEY is missing."
        )

    response = requests.get(
        VPLINK_API_URL,
        params={
            "api": VPLINK_API_KEY,
            "url": target_url,
        },
        timeout=20,
    )

    response.raise_for_status()

    # Try JSON first
    try:
        data = response.json()
    except Exception:
        data = None

    if isinstance(data, dict):

        possible_keys = [
            "shortenedUrl",
            "short_url",
            "shorturl",
            "shortened",
            "url",
            "link",
        ]

        for key in possible_keys:
            value = data.get(key)

            if (
                isinstance(value, str)
                and value.startswith(
                    ("http://", "https://")
                )
            ):
                return value

        result = data.get("result")

        if (
            isinstance(result, str)
            and result.startswith(
                ("http://", "https://")
            )
        ):
            return result

        if isinstance(result, dict):

            for key in possible_keys:
                value = result.get(key)

                if (
                    isinstance(value, str)
                    and value.startswith(
                        ("http://", "https://")
                    )
                ):
                    return value

    # Plain text response
    text = response.text.strip()

    if text.startswith(
        ("http://", "https://")
    ):
        return text

    raise RuntimeError(
        "Could not read VPLink response: "
        + response.text[:500]
    )


# =========================================================
# HTML
# =========================================================

def render_page(title, body):
    return f"""<!DOCTYPE html>
<html lang="en">
<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width,
    initial-scale=1.0"
>

<title>{title}</title>

<style>

* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;
    min-height: 100vh;

    display: flex;
    align-items: center;
    justify-content: center;

    padding: 20px;

    background: #0b0f14;
    color: #ffffff;

    font-family:
        Arial,
        Helvetica,
        sans-serif;
}}

.card {{
    width: 100%;
    max-width: 430px;

    padding: 28px 22px;

    background: #151b23;

    border: 1px solid #26303c;
    border-radius: 18px;

    text-align: center;

    box-shadow:
        0 16px 45px
        rgba(0, 0, 0, 0.35);
}}

h1 {{
    margin: 0 0 12px;
    font-size: 25px;
}}

p {{
    color: #b9c2cf;
    line-height: 1.55;
}}

.button {{
    display: block;

    width: 100%;

    margin-top: 18px;

    padding: 14px 18px;

    border-radius: 11px;

    background: #ffffff;
    color: #111820;

    text-decoration: none;

    font-size: 15px;
    font-weight: 700;
}}

.small {{
    margin-top: 16px;

    color: #7f8a98;

    font-size: 12px;
}}

.icon {{
    font-size: 42px;
    margin-bottom: 8px;
}}

</style>

</head>

<body>

<div class="card">

{body}

</div>

</body>
</html>
"""


def error_page(message):
    return HTMLResponse(
        render_page(
            "Lozo Gateway",
            f"""
            <div class="icon">⚠️</div>

            <h1>
                Something went wrong
            </h1>

            <p>
                {message}
            </p>
            """,
        ),
        status_code=400,
    )


# =========================================================
# HOME
# =========================================================

@app.get("/")
async def home():

    return HTMLResponse(
        render_page(
            "Lozo Gateway",
            """
            <h1>
                Lozo Gateway
            </h1>

            <p>
                Your secure gateway is active.
            </p>

            <div class="small">
                Powered by Lozo
            </div>
            """,
        )
    )


# =========================================================
# GATEWAY
# =========================================================

@app.get("/api/gateway")
async def gateway(
    request: Request,
    token: str = Query(...),
):

    token = token.strip()

    if not token:
        return error_page(
            "Invalid token."
        )

    try:

        # ---------------------------------------------
        # Check token in Supabase
        # ---------------------------------------------

        token_row = get_token(token)

        if not token_row:
            return error_page(
                "This link is invalid or has expired."
            )

        # ---------------------------------------------
        # Browser binding
        # ---------------------------------------------

        browser_id, is_new_browser = (
            get_or_create_browser_id(request)
        )

        # ---------------------------------------------
        # Create secure gateway state
        # ---------------------------------------------

        state = create_gateway_state(
            token,
            browser_id,
        )

        # ---------------------------------------------
        # VPLink destination
        # ---------------------------------------------

        complete_url = (
            f"{GATEWAY_DOMAIN}/api/complete?"
            + urlencode(
                {
                    "state": state,
                }
            )
        )

        # ---------------------------------------------
        # Create VPLink
        # ---------------------------------------------

        short_url = create_vplink(
            complete_url
        )

        # ---------------------------------------------
        # Redirect to VPLink
        # ---------------------------------------------

        response = RedirectResponse(
            short_url,
            status_code=302,
        )

        # Save browser identity
        if is_new_browser:

            response.set_cookie(
                key=BROWSER_COOKIE,
                value=browser_id,
                max_age=STATE_TTL_MINUTES * 60,

                httponly=True,
                secure=True,
                samesite="lax",
            )

        return response

    except Exception:

        return error_page(
            "Unable to create a secure session."
        )


# =========================================================
# COMPLETE
# =========================================================

@app.get("/api/complete")
async def complete(
    request: Request,
    state: str = Query(...),
    verify: int = Query(0),
):

    state = state.strip()

    if not state:
        return error_page(
            "Invalid session."
        )

    try:

        # ---------------------------------------------
        # Get state
        # ---------------------------------------------

        state_row = get_gateway_state(
            state
        )

        if not state_row:
            return error_page(
                "This gateway session does not exist."
            )

        # ---------------------------------------------
        # Used state
        # ---------------------------------------------

        if state_row.get("used"):
            return error_page(
                "This gateway session has already been used."
            )

        # ---------------------------------------------
        # State expiry
        # ---------------------------------------------

        expires_at = parse_datetime(
            state_row.get("expires_at")
        )

        if expires_at and expires_at <= now_utc():

            return error_page(
                "This gateway session has expired. "
                "Please generate a new link."
            )

        # ---------------------------------------------
        # Browser check
        # ---------------------------------------------

        browser_id = get_browser_id(
            request
        )

        if not browser_id:

            return error_page(
                "Browser verification failed. "
                "Please restart the link from Telegram."
            )

        saved_browser_hash = (
            state_row.get("browser_hash")
        )

        if (
            saved_browser_hash
            and saved_browser_hash
            != hash_browser(browser_id)
        ):

            return error_page(
                "Browser verification failed. "
                "Please restart the link from Telegram."
            )

        # ---------------------------------------------
        # Get original token
        # ---------------------------------------------

        token = state_row.get("token")

        if not token:
            return error_page(
                "Invalid gateway token."
            )

        # Token must still exist
        token_row = get_token(token)

        if not token_row:

            return error_page(
                "This file link is no longer available."
            )

        # =================================================
        # FINAL VERIFY BUTTON
        # =================================================

        if verify == 1:

            verify_expires_at = (
                state_row.get(
                    "verify_expires_at"
                )
            )

            verify_expiry = parse_datetime(
                verify_expires_at
            )

            if (
                verify_expiry
                and verify_expiry <= now_utc()
            ):

                return error_page(
                    "Verification expired. "
                    "Please generate a new link."
                )

            # -----------------------------------------
            # Mark state verified
            # -----------------------------------------

            update_gateway_state(
                state,
                {
                    "verified": True,
                    "verified_at": iso(
                        now_utc()
                    ),
                },
            )

            # -----------------------------------------
            # Telegram destination
            # -----------------------------------------

            target = create_telegram_link(
                token
            )

            if not target:

                return error_page(
                    "BOT_USERNAME is not configured."
                )

            # -----------------------------------------
            # Consume state
            # -----------------------------------------

            update_gateway_state(
                state,
                {
                    "used": True,
                },
            )

            response = RedirectResponse(
                target,
                status_code=302,
            )

            response.delete_cookie(
                VERIFIED_COOKIE
            )

            return response

        # =================================================
        # ALREADY VERIFIED
        # =================================================

        if state_row.get("verified"):

            target = create_telegram_link(
                token
            )

            if not target:

                return error_page(
                    "BOT_USERNAME is not configured."
                )

            update_gateway_state(
                state,
                {
                    "used": True,
                },
            )

            return RedirectResponse(
                target,
                status_code=302,
            )

        # =================================================
        # CREATE VERIFICATION WINDOW
        # =================================================

        verify_expires_at = (
            now_utc()
            + timedelta(
                minutes=VERIFY_TTL_MINUTES
            )
        )

        update_gateway_state(
            state,
            {
                "verify_expires_at": iso(
                    verify_expires_at
                ),
            },
        )

        # ---------------------------------------------
        # Verification URL
        # ---------------------------------------------

        verify_url = (
            f"{GATEWAY_DOMAIN}/api/complete?"
            + urlencode(
                {
                    "state": state,
                    "verify": "1",
                }
            )
        )

        return HTMLResponse(
            render_page(
                "Verify Link",
                f"""
                <h1>
                    Almost Done
                </h1>

                <p>
                    Your link has reached the
                    secure gateway.
                    Continue to receive your file.
                </p>

                <a
                    class="button"
                    href="{verify_url}"
                >
                    CONTINUE
                </a>

                <div class="small">
                    Verification is valid for
                    a limited time.
                </div>
                """,
            )
        )

    except Exception:

        return error_page(
            "Unable to verify this gateway session."
        )


# =========================================================
# HEALTH
# =========================================================

@app.get("/api/health")
async def health():

    return {
        "ok": True,
        "service": "lozo-gateway",
    }
