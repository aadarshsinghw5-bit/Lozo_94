import os
from urllib.parse import urlencode
from datetime import datetime, timezone

from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse
from supabase import create_client

app = FastAPI()

SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_SERVICE_ROLE_KEY = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
BOT_USERNAME = os.environ["BOT_USERNAME"].lstrip("@")

db = create_client(
    SUPABASE_URL,
    SUPABASE_SERVICE_ROLE_KEY
)


def make_page(title, body, status_code=200):
    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

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

            background: #0f1117;
            color: #ffffff;

            font-family: Arial, sans-serif;
        }}

        .card {{
            width: 100%;
            max-width: 430px;

            padding: 30px 22px;

            background: #191c24;

            border-radius: 18px;

            text-align: center;

            box-shadow:
                0 10px 35px rgba(0, 0, 0, 0.4);
        }}

        h2 {{
            margin: 0 0 12px;
            font-size: 24px;
        }}

        p {{
            margin: 0;
            color: #b8bec9;
            line-height: 1.6;
            font-size: 15px;
        }}

        .button {{
            display: inline-block;

            margin-top: 20px;
            padding: 13px 28px;

            background: #2ea6ff;
            color: white;

            text-decoration: none;

            border-radius: 12px;

            font-weight: bold;
            font-size: 15px;
        }}

        .button:hover {{
            opacity: 0.9;
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

    return HTMLResponse(
        content=html,
        status_code=status_code
    )


@app.get("/")
def home():
    return make_page(
        "Gateway",
        """
        <h2>✅ Gateway is running</h2>
        <p>
            Telegram file-store gateway is working correctly.
        </p>
        """
    )


@app.get("/api/gateway")
def gateway(
    token: str = Query(
        ...,
        min_length=10,
        max_length=100
    )
):

    # Get token from Supabase
    try:
        result = (
            db.table("tokens")
            .select(
                "token,user_id,target,expires_at,used"
            )
            .eq("token", token)
            .limit(1)
            .execute()
        )

    except Exception:
        return make_page(
            "Gateway Error",
            """
            <h2>⚠️ Temporary Error</h2>
            <p>
                Something went wrong.
                Please try again later.
            </p>
            """,
            503
        )

    # Token does not exist
    if not result.data:
        return make_page(
            "Invalid Link",
            """
            <h2>❌ Invalid or Expired Link</h2>
            <p>
                This link is no longer available.
            </p>
            """,
            404
        )

    row = result.data[0]

    # Already used
    if row.get("used"):
        return make_page(
            "Already Used",
            """
            <h2>❌ Link Already Used</h2>
            <p>
                This link can only be used once.
            </p>
            """,
            410
        )

    # Check expiry
    try:
        expires_at = datetime.fromisoformat(
            str(row["expires_at"]).replace(
                "Z",
                "+00:00"
            )
        )

        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(
                tzinfo=timezone.utc
            )

        if expires_at <= datetime.now(timezone.utc):
            return make_page(
                "Expired Link",
                """
                <h2>❌ Link Expired</h2>
                <p>
                    Please generate a new link.
                </p>
                """,
                410
            )

    except Exception:
        return make_page(
            "Invalid Link",
            """
            <h2>❌ Invalid Link</h2>
            <p>
                This link cannot be verified.
            </p>
            """,
            400
        )

    # Telegram verification URL
    verify_url = (
        f"https://t.me/{BOT_USERNAME}?"
        + urlencode({
            "start": f"verify_{token}"
        })
    )

    # Gateway page
    return make_page(
        "Continue",
        f"""
        <h2>🔐 Link Verification</h2>

        <p>
            Tap the button below to continue
            to Telegram.
        </p>

        <a
            class="button"
            href="{verify_url}"
        >
            CONTINUE
        </a>
        """
    )
