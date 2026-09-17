import os
import secrets
import hashlib
import html
import time
from datetime import datetime, timezone, timedelta
from urllib.parse import urlencode

import requests
from fastapi import FastAPI, Request, Query
from fastapi.responses import (
    HTMLResponse,
    RedirectResponse,
    JSONResponse,
)

from supabase import create_client, Client


# ============================================================
# CONFIG
# ============================================================

SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()

BOT_USERNAME = os.getenv("BOT_USERNAME", "").strip().lstrip("@")

VPLINK_API_URL = os.getenv(
    "VPLINK_API_URL",
    "https://vplink.in/api"
).rstrip("/")

VPLINK_API_KEY = os.getenv("VPLINK_API_KEY", "").strip()

GATEWAY_DOMAIN = os.getenv(
    "GATEWAY_DOMAIN",
    "https://lozo-94.vercel.app"
).rstrip("/")

# How long a gateway session remains valid.
SESSION_MINUTES = int(os.getenv("GATEWAY_SESSION_MINUTES", "30"))

# How long the manual verification remains valid.
VERIFY_MINUTES = int(os.getenv("VERIFY_MINUTES", "10"))


# ============================================================
# APP
# ============================================================

app = FastAPI()


# ============================================================
# SUPABASE
# ============================================================

if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
    supabase: Client | None = None
else:
    supabase = create_client(
        SUPABASE_URL,
        SUPABASE_SERVICE_ROLE_KEY
    )


# ============================================================
# HELPERS
# ============================================================

def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def random_token(length: int = 32) -> str:
    return secrets.token_urlsafe(length)


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def db_ready():
    return supabase is not None


def error_page(title: str, message: str, code: int = 400):
    return HTMLResponse(
        f"""
        <!doctype html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport"
                  content="width=device-width,initial-scale=1">
            <title>{html.escape(title)}</title>
            <style>
                body {{
                    margin:0;
                    background:#0f1115;
                    color:#fff;
                    font-family:Arial,sans-serif;
                    display:flex;
                    justify-content:center;
                    align-items:center;
                    min-height:100vh;
                    padding:20px;
                    box-sizing:border-box;
                }}

                .box {{
                    max-width:430px;
                    width:100%;
                    background:#181b22;
                    border-radius:18px;
                    padding:28px;
                    text-align:center;
                    box-sizing:border-box;
                    box-shadow:0 10px 40px rgba(0,0,0,.35);
                }}

                h2 {{
                    margin-top:0;
                }}

                p {{
                    color:#bfc4ce;
                    line-height:1.5;
                }}

                .icon {{
                    font-size:48px;
                    margin-bottom:10px;
                }}
            </style>
        </head>

        <body>
            <div class="box">
                <div class="icon">⚠️</div>
                <h2>{html.escape(title)}</h2>
                <p>{html.escape(message)}</p>
            </div>
        </body>
        </html>
        """,
        status_code=code,
    )


def get_token_record(token: str):
    if not db_ready():
        return None

    try:
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

    except Exception as e:
        print("Supabase token lookup error:", repr(e))
        return None


def get_session(state: str):
    if not db_ready():
        return None

    try:
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

    except Exception as e:
        print("Supabase gateway state lookup error:", repr(e))
        return None


def save_session(
    state: str,
    token: str,
    expires_at: datetime,
    challenge_hash: str,
):
    if not db_ready():
        raise RuntimeError("Supabase is not configured")

    data = {
        "state": state,
        "token": token,
        "expires_at": iso(expires_at),
        "used": False,
        "challenge_hash": challenge_hash,
        "verified": False,
        "verified_at": None,
    }

    supabase.table("gateway_states").insert(data).execute()


def update_session(state: str, values: dict):
    if not db_ready():
        return

    try:
        (
            supabase
            .table("gateway_states")
            .update(values)
            .eq("state", state)
            .execute()
        )
    except Exception as e:
        print("Supabase gateway state update error:", repr(e))


def delete_session(state: str):
    if not db_ready():
        return

    try:
        (
            supabase
            .table("gateway_states")
            .delete()
            .eq("state", state)
            .execute()
        )
    except Exception as e:
        print("Supabase gateway state delete error:", repr(e))


def parse_datetime(value):
    if not value:
        return None

    try:
        value = str(value)

        if value.endswith("Z"):
            value = value[:-1] + "+00:00"

        dt = datetime.fromisoformat(value)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        return dt.astimezone(timezone.utc)

    except Exception:
        return None


# ============================================================
# VP LINKS
# ============================================================

def create_vplink(destination: str) -> str | None:
    """
    Tries common VP Links API parameter layouts.

    Expected environment:
        VPLINK_API_URL
        VPLINK_API_KEY
    """

    if not VPLINK_API_KEY:
        print("VPLINK_API_KEY missing")
        return None

    candidates = [
        {
            "api": VPLINK_API_KEY,
            "url": destination,
        },
        {
            "api_key": VPLINK_API_KEY,
            "url": destination,
        },
        {
            "key": VPLINK_API_KEY,
            "url": destination,
        },
    ]

    headers_list = [
        {},
        {
            "Authorization": f"Bearer {VPLINK_API_KEY}"
        },
    ]

    for payload in candidates:
        for headers in headers_list:
            try:
                response = requests.get(
                    VPLINK_API_URL,
                    params=payload,
                    headers=headers,
                    timeout=15,
                )

                print(
                    "VPLink:",
                    response.status_code,
                    response.text[:500]
                )

                if response.status_code >= 400:
                    continue

                try:
                    data = response.json()
                except Exception:
                    data = {}

                # Common response fields.
                for key in (
                    "shortenedUrl",
                    "short_url",
                    "shorturl",
                    "url",
                    "link",
                    "shortened",
                    "result",
                ):
                    value = data.get(key)

                    if isinstance(value, str):
                        if value.startswith("http://") or value.startswith("https://"):
                            return value

                # Some APIs return nested result.
                result = data.get("result")

                if isinstance(result, dict):
                    for key in (
                        "url",
                        "link",
                        "short_url",
                        "shortenedUrl",
                    ):
                        value = result.get(key)

                        if isinstance(value, str):
                            if value.startswith("http://") or value.startswith("https://"):
                                return value

            except Exception as e:
                print("VPLink request error:", repr(e))

    return None


# ============================================================
# HOME / HEALTH
# ============================================================

@app.get("/")
async def home():
    return {
        "ok": True,
        "service": "lozo-gateway",
        "status": "running",
    }


@app.get("/health")
async def health():
    return {
        "ok": True,
    }


# ============================================================
# MAIN GATEWAY
# ============================================================

@app.get("/api/gateway")
async def gateway(
    token: str = Query(default="")
):
    """
    Telegram bot sends users here:

        /api/gateway?token=XXXX

    We DO NOT expose the Telegram deep link to VP Links.

    Instead:
        token
          ↓
        random state
          ↓
        /api/complete?state=...
          ↓
        VP Links
    """

    if not token:
        return error_page(
            "Invalid Link",
            "This gateway link is missing its token."
        )

    if not db_ready():
        return error_page(
            "Gateway Error",
            "Gateway database is not configured.",
            500
        )

    record = get_token_record(token)

    if not record:
        return error_page(
            "Invalid Link",
            "This file link is invalid or no longer exists."
        )

    # IMPORTANT:
    # Do NOT reject based on used here if your bot is responsible
    # for finally consuming the original token.
    #
    # We only check obvious expiry if expires_at exists.

    expires = parse_datetime(record.get("expires_at"))

    if expires and expires < now_utc():
        return error_page(
            "Link Expired",
            "This file link has expired."
        )

    # --------------------------------------------------------
    # Generate completely random gateway state.
    # --------------------------------------------------------

    state = random_token(32)

    # Browser challenge.
    challenge = random_token(24)
    challenge_hash = sha256(challenge)

    session_expiry = now_utc() + timedelta(
        minutes=SESSION_MINUTES
    )

    try:
        save_session(
            state=state,
            token=token,
            expires_at=session_expiry,
            challenge_hash=challenge_hash,
        )
    except Exception as e:
        print("Session creation error:", repr(e))

        return error_page(
            "Gateway Error",
            "Unable to create a secure session.",
            500
        )

    # --------------------------------------------------------
    # VP destination.
    #
    # IMPORTANT:
    # Telegram URL is NEVER given to VP Links.
    # --------------------------------------------------------

    complete_url = (
        f"{GATEWAY_DOMAIN}/api/complete?"
        f"{urlencode({'state': state})}"
    )

    short_url = create_vplink(complete_url)

    if not short_url:
        delete_session(state)

        return error_page(
            "Shortener Error",
            "Unable to create the verification link. Please try again.",
            502
        )

    # --------------------------------------------------------
    # Show a simple start page before redirect.
    # --------------------------------------------------------

    return HTMLResponse(
        f"""
        <!doctype html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport"
                  content="width=device-width,initial-scale=1">

            <meta http-equiv="refresh"
                  content="0;url={html.escape(short_url)}">

            <title>Secure Access</title>

            <style>
                body {{
                    margin:0;
                    background:#0f1115;
                    color:white;
                    font-family:Arial,sans-serif;
                    display:flex;
                    align-items:center;
                    justify-content:center;
                    min-height:100vh;
                }}

                .box {{
                    text-align:center;
                    background:#181b22;
                    padding:30px;
                    border-radius:20px;
                    width:min(420px,90%);
                    box-sizing:border-box;
                }}

                .loader {{
                    width:42px;
                    height:42px;
                    border:4px solid #444;
                    border-top-color:#fff;
                    border-radius:50%;
                    animation:spin 1s linear infinite;
                    margin:0 auto 18px;
                }}

                @keyframes spin {{
                    to {{
                        transform:rotate(360deg);
                    }}
                }}

                p {{
                    color:#bbb;
                }}

                a {{
                    color:white;
                }}
            </style>
        </head>

        <body>
            <div class="box">
                <div class="loader"></div>
                <h2>Preparing Secure Link</h2>
                <p>Please wait...</p>
                <p>
                    <a href="{html.escape(short_url)}">
                        Continue
                    </a>
                </p>
            </div>
        </body>
        </html>
        """,
        status_code=200,
    )


# ============================================================
# COMPLETE
# ============================================================

@app.get("/api/complete")
async def complete(
    request: Request,
    state: str = Query(default="")
):
    """
    VP Links should eventually redirect here.

    We intentionally DO NOT immediately redirect to Telegram.

    First visit:
        /api/complete?state=XYZ

    shows manual verification.

    After verification:
        verified cookie
        ↓
        Telegram
    """

    if not state:
        return error_page(
            "Verification Required",
            "Please manually verify. Don't try to bypass."
        )

    session = get_session(state)

    if not session:
        return error_page(
            "Session Not Found",
            "This verification session is invalid or expired."
        )

    expires = parse_datetime(session.get("expires_at"))

    if expires and expires < now_utc():
        delete_session(state)

        return error_page(
            "Session Expired",
            "Please generate a new file link."
        )

    # Already consumed.
    if session.get("used"):
        return error_page(
            "Link Already Used",
            "This file link has already been used."
        )

    verified = bool(session.get("verified"))

    if verified:
        return await finish_delivery(
            request=request,
            state=state,
            session=session,
        )

    # --------------------------------------------------------
    # Manual verification page.
    # --------------------------------------------------------

    challenge = random_token(24)

    # Store only hash server-side.
    update_session(
        state,
        {
            "challenge_hash": sha256(challenge)
        }
    )

    return HTMLResponse(
        verification_page(
            state=state,
            challenge=challenge,
        )
    )


# ============================================================
# MANUAL VERIFY
# ============================================================

@app.get("/verify/{state}")
async def verify_page(
    request: Request,
    state: str,
    challenge: str = Query(default="")
):
    """
    Verification endpoint.

    This endpoint requires:
      - valid state
      - valid challenge
      - browser-generated verification request
    """

    if not state:
        return error_page(
            "Verification Failed",
            "Please manually verify. Don't try to bypass."
        )

    session = get_session(state)

    if not session:
        return error_page(
            "Verification Failed",
            "This verification session is invalid."
        )

    expires = parse_datetime(session.get("expires_at"))

    if expires and expires < now_utc():
        delete_session(state)

        return error_page(
            "Session Expired",
            "Please generate a new link."
        )

    # --------------------------------------------------------
    # Challenge verification
    # --------------------------------------------------------

    if not challenge:
        return error_page(
            "Verification Required",
            "Please manually verify. Don't try to bypass."
        )

    expected_hash = session.get("challenge_hash")

    if not expected_hash:
        return error_page(
            "Verification Failed",
            "Verification challenge is missing."
        )

    if not secrets.compare_digest(
        sha256(challenge),
        expected_hash
    ):
        return error_page(
            "Verification Failed",
            "Invalid verification challenge."
        )

    # --------------------------------------------------------
    # Mark gateway session verified.
    # --------------------------------------------------------

    verified_until = now_utc() + timedelta(
        minutes=VERIFY_MINUTES
    )

    update_session(
        state,
        {
            "verified": True,
            "verified_at": iso(now_utc()),
            "verify_expires_at": iso(verified_until),
        }
    )

    # Secure-ish browser cookie.
    response = RedirectResponse(
        url=f"{GATEWAY_DOMAIN}/api/complete?"
            f"{urlencode({'state': state})}",
        status_code=303,
    )

    response.set_cookie(
        key="gateway_verified",
        value=sha256(state),
        max_age=VERIFY_MINUTES * 60,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
    )

    return response


# ============================================================
# FINISH DELIVERY
# ============================================================

async def finish_delivery(
    request: Request,
    state: str,
    session: dict,
):
    """
    Final Telegram redirect.

    IMPORTANT:
    We don't mark the original token as used here.

    The Telegram bot should consume it when /start verify_TOKEN
    is actually received.
    """

    # --------------------------------------------------------
    # Verify browser cookie.
    # --------------------------------------------------------

    cookie = request.cookies.get("gateway_verified")

    expected_cookie = sha256(state)

    if not cookie or not secrets.compare_digest(
        cookie,
        expected_cookie
    ):
        # No verification cookie.
        #
        # Instead of giving the Telegram URL away, send the user
        # back to manual verification.
        return HTMLResponse(
            verification_page(
                state=state,
                challenge=random_token(24),
            )
        )

    # --------------------------------------------------------
    # Verify session.
    # --------------------------------------------------------

    verify_expiry = parse_datetime(
        session.get("verify_expires_at")
    )

    if verify_expiry and verify_expiry < now_utc():
        update_session(
            state,
            {
                "verified": False,
                "verified_at": None,
                "verify_expires_at": None,
            }
        )

        return error_page(
            "Verification Expired",
            "Please manually verify again."
        )

    token = session.get("token")

    if not token:
        return error_page(
            "Invalid Session",
            "The original file token is missing."
        )

    original = get_token_record(token)

    if not original:
        return error_page(
            "File Not Found",
            "The original file link no longer exists."
        )

    # --------------------------------------------------------
    # Telegram destination.
    # --------------------------------------------------------

    if not BOT_USERNAME:
        return error_page(
            "Gateway Configuration Error",
            "BOT_USERNAME is missing.",
            500
        )

    telegram_url = (
        f"https://t.me/{BOT_USERNAME}"
        f"?start=verify_{token}"
    )

    # --------------------------------------------------------
    # IMPORTANT:
    #
    # Marking this gateway state used is okay because this
    # particular gateway session is now consumed.
    #
    # The original `tokens.used` is NOT changed here.
    # --------------------------------------------------------

    update_session(
        state,
        {
            "used": True,
        }
    )

    response = RedirectResponse(
        url=telegram_url,
        status_code=302,
    )

    # Remove verification cookie after successful handoff.
    response.delete_cookie(
        key="gateway_verified",
        path="/",
    )

    return response


# ============================================================
# VERIFICATION HTML
# ============================================================

def verification_page(
    state: str,
    challenge: str,
) -> str:

    safe_state = html.escape(state, quote=True)
    safe_challenge = html.escape(challenge, quote=True)

    verify_url = (
        f"{GATEWAY_DOMAIN}/verify/"
        f"{safe_state}?"
        f"{urlencode({'challenge': challenge})}"
    )

    return f"""
    <!doctype html>

    <html>
    <head>
        <meta charset="utf-8">

        <meta
            name="viewport"
            content="width=device-width,initial-scale=1"
        >

        <meta
            name="robots"
            content="noindex,nofollow,noarchive"
        >

        <title>Manual Verification</title>

        <style>

            * {{
                box-sizing:border-box;
            }}

            body {{
                margin:0;
                min-height:100vh;
                display:flex;
                justify-content:center;
                align-items:center;

                background:
                    radial-gradient(
                        circle at top,
                        #20242d,
                        #0b0d11 60%
                    );

                color:#fff;
                font-family:
                    Arial,
                    Helvetica,
                    sans-serif;

                padding:20px;
            }}

            .card {{
                width:100%;
                max-width:430px;

                background:rgba(24,27,34,.96);

                border:1px solid
                    rgba(255,255,255,.08);

                border-radius:22px;

                padding:30px;

                box-shadow:
                    0 20px 60px
                    rgba(0,0,0,.45);

                text-align:center;
            }}

            .shield {{
                width:72px;
                height:72px;

                display:flex;
                align-items:center;
                justify-content:center;

                margin:0 auto 20px;

                border-radius:50%;

                background:#242933;

                font-size:34px;
            }}

            h1 {{
                margin:0 0 10px;
                font-size:24px;
            }}

            .sub {{
                margin:0 0 25px;
                color:#aeb4bf;
                line-height:1.5;
            }}

            .verify-box {{
                display:flex;
                align-items:center;

                gap:14px;

                padding:18px;

                border-radius:14px;

                background:#11141a;

                border:1px solid
                    rgba(255,255,255,.08);

                text-align:left;

                cursor:pointer;

                user-select:none;
            }}

            .checkbox {{
                width:25px;
                height:25px;

                border-radius:6px;

                border:2px solid #707784;

                flex:none;

                display:flex;
                align-items:center;
                justify-content:center;

                transition:.2s;
            }}

            .checkbox.checked {{
                background:#fff;
                border-color:#fff;
                color:#111;
            }}

            .checkbox.checked::after {{
                content:"✓";
                font-weight:bold;
            }}

            .verify-text {{
                font-size:15px;
                line-height:1.3;
            }}

            button {{
                width:100%;

                margin-top:18px;

                padding:14px 18px;

                border:0;
                border-radius:12px;

                background:#fff;
                color:#111;

                font-size:16px;
                font-weight:bold;

                cursor:pointer;

                opacity:.45;

                pointer-events:none;
            }}

            button.active {{
                opacity:1;
                pointer-events:auto;
            }}

            .warning {{
                margin-top:20px;

                color:#858c98;

                font-size:12px;
                line-height:1.5;
            }}

            .spinner {{
                width:18px;
                height:18px;

                border:2px solid #aaa;
                border-top-color:#111;

                border-radius:50%;

                display:inline-block;

                animation:spin .8s linear infinite;

                vertical-align:middle;

                margin-right:8px;
            }}

            @keyframes spin {{
                to {{
                    transform:rotate(360deg);
                }}
            }}

        </style>
    </head>

    <body>

        <div class="card">

            <div class="shield">
                🛡️
            </div>

            <h1>
                Manual Verification
            </h1>

            <p class="sub">
                Please manually verify.
                Don't try to bypass.
            </p>

            <div
                class="verify-box"
                id="verifyBox"
                onclick="toggleVerify()"
            >

                <div
                    class="checkbox"
                    id="checkbox"
                ></div>

                <div class="verify-text">
                    I am a human and I want to continue
                </div>

            </div>

            <button
                id="continueBtn"
                onclick="continueVerification()"
            >
                Continue
            </button>

            <div class="warning">
                This verification session is temporary
                and can only be used once.
            </div>

        </div>


        <script>

            const state =
                "{safe_state}";

            const challenge =
                "{safe_challenge}";

            const verifyUrl =
                "{verify_url}";

            let checked = false;


            function toggleVerify() {{

                checked = !checked;

                const box =
                    document.getElementById(
                        "checkbox"
                    );

                const button =
                    document.getElementById(
                        "continueBtn"
                    );

                if (checked) {{

                    box.classList.add(
                        "checked"
                    );

                    button.classList.add(
                        "active"
                    );

                }} else {{

                    box.classList.remove(
                        "checked"
                    );

                    button.classList.remove(
                        "active"
                    );

                }}

            }}


            function continueVerification() {{

                if (!checked) {{
                    return;
                }}

                const button =
                    document.getElementById(
                        "continueBtn"
                    );

                button.classList.remove(
                    "active"
                );

                button.innerHTML =
                    '<span class="spinner"></span>'
                    + 'Verifying...';

                /*
                 * Small delay makes accidental automatic
                 * navigation less likely.
                 */

                setTimeout(function() {{

                    window.location.href =
                        verifyUrl;

                }}, 900);

            }}

        </script>

    </body>
    </html>
    """


# ============================================================
# DEBUG / INFO
# ============================================================

@app.get("/api/session")
async def session_info(
    state: str = Query(default="")
):
    """
    Safe diagnostic endpoint.
    Does NOT return original Telegram target/token.
    """

    if not state:
        return JSONResponse(
            {
                "ok": False,
                "error": "missing_state",
            },
            status_code=400,
        )

    session = get_session(state)

    if not session:
        return JSONResponse(
            {
                "ok": False,
                "error": "not_found",
            },
            status_code=404,
        )

    expires = parse_datetime(
        session.get("expires_at")
    )

    return {
        "ok": True,
        "exists": True,
        "expired": bool(
            expires and expires < now_utc()
        ),
        "verified": bool(
            session.get("verified")
        ),
        "used": bool(
            session.get("used")
        ),
    }
