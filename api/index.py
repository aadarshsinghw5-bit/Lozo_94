import os
from datetime import datetime, timezone

import requests
from fastapi import FastAPI, Query
from fastapi.responses import RedirectResponse, HTMLResponse
from supabase import create_client


app = FastAPI()


SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()

SUPABASE_SERVICE_ROLE_KEY = os.getenv(
    "SUPABASE_SERVICE_ROLE_KEY",
    ""
).strip()

BOT_USERNAME = os.getenv(
    "BOT_USERNAME",
    ""
).strip().lstrip("@")

AROLINKS_API_URL = os.getenv(
    "AROLINKS_API_URL",
    "https://arolinks.com/api"
).strip()

AROLINKS_API_KEY = os.getenv(
    "AROLINKS_API_KEY",
    ""
).strip()


def error_page(message: str, status_code: int = 400):
    return HTMLResponse(
        content=f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Gateway</title>
            <style>
                body {{
                    background: #111827;
                    color: white;
                    font-family: Arial, sans-serif;
                    text-align: center;
                    padding: 50px 18px;
                }}

                .box {{
                    max-width: 420px;
                    margin: auto;
                    padding: 28px;
                    border-radius: 16px;
                    background: #1f2937;
                }}

                h2 {{
                    margin: 0;
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


def get_supabase():
    if not SUPABASE_URL:
        raise RuntimeError("SUPABASE_URL is missing")

    if not SUPABASE_SERVICE_ROLE_KEY:
        raise RuntimeError("SUPABASE_SERVICE_ROLE_KEY is missing")

    return create_client(
        SUPABASE_URL,
        SUPABASE_SERVICE_ROLE_KEY
    )


@app.get("/")
async def home():
    return {
        "status": "ok",
        "service": "lozo-94-gateway"
    }


@app.get("/health")
async def health():
    return {
        "status": "ok"
    }


@app.get("/api/gateway")
async def gateway(
    token: str = Query(...)
):
    token = token.strip()

    if not token or len(token) < 10:
        return error_page("❌ Invalid link.")

    if not BOT_USERNAME:
        return error_page(
            "⚠️ BOT_USERNAME is missing in Vercel."
        )

    if not AROLINKS_API_KEY:
        return error_page(
            "⚠️ AROLinks API key is missing in Vercel."
        )

    try:
        supabase = get_supabase()

        result = (
            supabase
            .table("tokens")
            .select("token,user_id,target,expires_at,used")
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

        if row.get("used") is True:
            return error_page(
                "❌ This link has already been used."
            )

        expires_at = row.get("expires_at")

        if not expires_at:
            return error_page(
                "❌ This link has no expiry."
            )

        try:
            expiry = datetime.fromisoformat(
                str(expires_at).replace("Z", "+00:00")
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

        telegram_url = (
            f"https://t.me/{BOT_USERNAME}"
            f"?start=verify_{token}"
        )

        shortener_response = requests.get(
            AROLINKS_API_URL,
            params={
                "api": AROLINKS_API_KEY,
                "url": telegram_url
            },
            timeout=20
        )

        shortener_response.raise_for_status()

        try:
            data = shortener_response.json()
        except Exception:
            return error_page(
                "⚠️ AroLinks returned an invalid response."
            )

        if data.get("status") != "success":
            return error_page(
                "⚠️ AroLinks could not create the link."
            )

        shortened_url = (
            data.get("shortenedUrl")
            or data.get("shortened_url")
        )

        if not shortened_url:
            return error_page(
                "⚠️ AroLinks link was not received."
            )

        return RedirectResponse(
            url=shortened_url,
            status_code=302
        )

    except Exception as error:
        print("GATEWAY ERROR:", repr(error))

        return error_page(
            "⚠️ Gateway error. Please try again later.",
            status_code=500
    )
