import os
import requests

from fastapi import FastAPI, Query
from fastapi.responses import RedirectResponse, HTMLResponse
from supabase import create_client, Client


app = FastAPI()


SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()

BOT_USERNAME = os.getenv("BOT_USERNAME", "").strip().lstrip("@")

AROLINKS_API_URL = os.getenv(
    "AROLINKS_API_URL",
    "https://arolinks.com/api"
).strip()

AROLINKS_API_KEY = os.getenv("AROLINKS_API_KEY", "").strip()


def get_supabase() -> Client:
    return create_client(
        SUPABASE_URL,
        SUPABASE_SERVICE_ROLE_KEY
    )


def error_page(message: str):
    return HTMLResponse(
        f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Link Error</title>
            <style>
                body {{
                    background:#111;
                    color:white;
                    font-family:Arial,sans-serif;
                    text-align:center;
                    padding:60px 20px;
                }}
                .box {{
                    max-width:420px;
                    margin:auto;
                    padding:30px;
                    border-radius:16px;
                    background:#1d1d1d;
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
        status_code=400
    )


@app.get("/")
async def home():
    return {
        "status": "ok",
        "service": "shortener-gateway"
    }


@app.get("/health")
async def health():
    return {
        "status": "ok"
    }


@app.get("/api/gateway")
async def gateway(
    token: str = Query(..., min_length=10)
):
    # Basic configuration check
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        return error_page("⚠️ Gateway is not configured correctly.")

    if not BOT_USERNAME:
        return error_page("⚠️ Bot username is not configured.")

    if not AROLINKS_API_KEY:
        return error_page("⚠️ Shortener is not configured correctly.")

    try:
        supabase = get_supabase()

        # Check token in Supabase
        result = (
            supabase
            .table("tokens")
            .select("*")
            .eq("token", token)
            .limit(1)
            .execute()
        )

        rows = result.data or []

        if not rows:
            return error_page("❌ Invalid or expired link.")

        row = rows[0]

        # Already used
        if row.get("used") is True:
            return error_page("❌ This link has already been used.")

        # Check expiry
        expires_at = row.get("expires_at")

        if not expires_at:
            return error_page("❌ Invalid link.")

        from datetime import datetime, timezone

        try:
            expiry = datetime.fromisoformat(
                expires_at.replace("Z", "+00:00")
            )

            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)

            if datetime.now(timezone.utc) >= expiry:
                return error_page("❌ This link has expired.")

        except Exception:
            return error_page("❌ Invalid link expiry.")

        # Telegram verification destination
        verify_url = (
            f"https://t.me/{BOT_USERNAME}"
            f"?start=verify_{token}"
        )

        # Create AroLinks short URL
        response = requests.get(
            AROLINKS_API_URL,
            params={
                "api": AROLINKS_API_KEY,
                "url": verify_url
            },
            timeout=20
        )

        response.raise_for_status()

        try:
            data = response.json()
        except Exception:
            return error_page("⚠️ Shortener returned an invalid response.")

        if data.get("status") != "success":
            return error_page("⚠️ Unable to create shortener link.")

        shortened_url = (
            data.get("shortenedUrl")
            or data.get("shortened_url")
        )

        if not shortened_url:
            return error_page("⚠️ Shortener did not return a link.")

        # Final flow:
        # Gateway → AroLinks → Telegram Verify
        return RedirectResponse(
            url=shortened_url,
            status_code=302
        )

    except Exception:
        return error_page(
            "⚠️ Something went wrong. Please try again later."
        )
