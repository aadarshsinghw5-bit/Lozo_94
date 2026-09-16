import os
from datetime import datetime, timezone

import requests
from fastapi import FastAPI, Query
from fastapi.responses import RedirectResponse, HTMLResponse
from supabase import create_client


app = FastAPI()


# =========================
# ENVIRONMENT VARIABLES
# =========================

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


# =========================
# ERROR PAGE
# =========================

def error_page(message: str, status_code: int = 400):
    return HTMLResponse(
        content=f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta name="viewport" content="width=device-width, initial-scale=1">
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


# =========================
# SUPABASE CLIENT
# =========================

def get_supabase():
    if not SUPABASE_URL:
        raise RuntimeError("SUPABASE_URL is missing")

    if not SUPABASE_SERVICE_ROLE_KEY:
        raise RuntimeError(
            "SUPABASE_SERVICE_ROLE_KEY is missing"
        )

    return create_client(
        SUPABASE_URL,
        SUPABASE_SERVICE_ROLE_KEY
    )


# =========================
# HOME ROUTE
# =========================

@app.get("/")
async def home():
    return {
        "status": "ok",
        "service": "lozo-94-gateway"
    }


# =========================
# HEALTH ROUTE
# =========================

@app.get("/health")
async def health():
    return {
        "status": "ok"
    }


# =========================
# MAIN GATEWAY
# =========================

@app.get("/api/gateway")
async def gateway(
    token: str = Query(...)
):
    token = token.strip()

    # Basic token validation
    if not token or len(token) < 10:
        return error_page(
            "❌ Invalid link."
        )

    # Bot username check
    if not BOT_USERNAME:
        return error_page(
            "⚠️ BOT_USERNAME is missing in Vercel."
        )

    # VPLINK API key check
    if not VPLINK_API_KEY:
        return error_page(
            "⚠️ VPLINK API key is missing in Vercel."
        )

    try:
        supabase = get_supabase()

        # =========================
        # CHECK TOKEN IN SUPABASE
        # =========================

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
            return error_page(
                "❌ This link is invalid or expired."
            )

        row = rows[0]

        # Already used check
        if row.get("used") is True:
            return error_page(
                "❌ This link has already been used."
            )

        # =========================
        # EXPIRY CHECK
        # =========================

        expires_at = row.get("expires_at")

        if not expires_at:
            return error_page(
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

            if datetime.now(timezone.utc) >= expiry:
                return error_page(
                    "❌ This link has expired."
                )

        except Exception:
            return error_page(
                "❌ Invalid expiry information."
            )

        # =========================
        # TELEGRAM DESTINATION
        # =========================

        telegram_url = (
            f"https://t.me/{BOT_USERNAME}"
            f"?start=verify_{token}"
        )

        # =========================
        # VPLINK API REQUEST
        # =========================

        response = requests.get(
            VPLINK_API_URL,
            params={
                "api": VPLINK_API_KEY,
                "url": telegram_url
            },
            timeout=20
        )

        response.raise_for_status()

        # =========================
        # PARSE VPLINK RESPONSE
        # =========================

        try:
            data = response.json()

        except Exception:
            return error_page(
                "⚠️ VPLINK returned an invalid response."
            )

        if data.get("status") != "success":
            message = data.get(
                "message",
                "VPLINK could not create the link."
            )

            return error_page(
                f"⚠️ {message}"
            )

        shortened_url = (
            data.get("shortenedUrl")
            or data.get("shortened_url")
        )

        if not shortened_url:
            return error_page(
                "⚠️ VPLINK link was not received."
            )

        # =========================
        # REDIRECT TO VPLINK
        # =========================

        return RedirectResponse(
            url=shortened_url,
            status_code=302
        )

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
