import os
import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from urllib.parse import quote

import requests
from fastapi import FastAPI, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from supabase import create_client, Client


app = FastAPI()


# =========================
# ENVIRONMENT VARIABLES
# =========================

SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")

BOT_USERNAME = os.getenv("BOT_USERNAME", "").lstrip("@")

VPLINK_API_URL = os.getenv(
    "VPLINK_API_URL",
    "https://vplink.in/api"
).rstrip("/")

VPLINK_API_KEY = os.getenv("VPLINK_API_KEY", "")

GATEWAY_DOMAIN = os.getenv(
    "GATEWAY_DOMAIN",
    "https://lozo-94.vercel.app"
).rstrip("/")


# =========================
# SUPABASE
# =========================

supabase: Client = create_client(
    SUPABASE_URL,
    SUPABASE_SERVICE_ROLE_KEY
)


# =========================
# SETTINGS
# =========================

STATE_TTL_MINUTES = 30
VERIFY_TTL_MINUTES = 10

BROWSER_COOKIE = "lozo_browser_id"
VERIFIED_COOKIE = "lozo_verified"


# =========================
# HELPERS
# =========================

def now_utc():
    return datetime.now(timezone.utc)


def iso_now():
    return now_utc().isoformat()


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def html_page(title: str, body: str) -> HTMLResponse:
    return HTMLResponse(
        f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width, initial-scale=1.0">

    <title>{title}</title>

    <style>
        * {{
            box-sizing: border-box;
        }}

        body {{
            margin: 0;
            min-height: 100vh;
            background: #0f1115;
            color: white;
            font-family: Arial, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }}

        .card {{
            width: 100%;
            max-width: 430px;
            background: #181b21;
            border-radius: 18px;
            padding: 28px;
            text-align: center;
            box-shadow: 0 10px 40px rgba(0,0,0,.35);
        }}

        h1 {{
            margin-top: 0;
            font-size: 25px;
        }}

        p {{
            color: #c7cbd1;
            line-height: 1.6;
        }}

        .btn {{
            display: inline-block;
            width: 100%;
            padding: 14px;
            margin-top: 15px;
            border-radius: 12px;
            background: #2f81f7;
            color: white;
            text-decoration: none;
            font-weight: bold;
        }}

        .success {{
            color: #58d68d;
        }}

        .error {{
            color: #ff6b6b;
        }}

        .small {{
            font-size: 13px;
            color: #9298a3;
            margin-top: 15px;
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
    )


def error_page(message: str):
    return html_page(
        "Gateway Error",
        f"""
        <h1 class="error">Gateway Error</h1>
        <p>{message}</p>
        """
    )


def verification_page(state: str):
    verify_url = f"{GATEWAY_DOMAIN}/verify/{quote(state)}"

    return html_page(
        "Verification",
        f"""
        <h1>Verification Required</h1>

        <p>
            Please manually verify to continue.
        </p>

        <a class="btn" href="{verify_url}">
            VERIFY
        </a>

        <p class="small">
            Do not switch browser or device during verification.
        </p>
        """
    )


def success_page():
    return html_page(
        "Verified",
        """
        <h1 class="success">Verification Successful</h1>

        <p>
            Your verification is complete.
            Redirecting to Telegram...
        </p>

        <script>
            setTimeout(function() {
                window.location.href = "/";
            }, 1000);
        </script>
        """
    )


# =========================
# CREATE VP LINK
# =========================

def create_vplink(destination: str) -> str:
    """
    Creates a VPLink URL.

    Adjust the payload below if your VPLINK API
    uses different parameter names.
    """

    params = {
        "api": VPLINK_API_KEY,
        "url": destination
    }

    response = requests.get(
        VPLINK_API_URL,
        params=params,
        timeout=15
    )

    if response.status_code != 200:
        raise RuntimeError(
            f"VPLink HTTP {response.status_code}"
        )

    data = response.json()

    # Common response formats
    short_url = (
        data.get("shortenedUrl")
        or data.get("shortened_url")
        or data.get("url")
        or data.get("link")
    )

    if not short_url:
        raise RuntimeError(
            f"VPLink API returned unexpected response: {data}"
        )

    return short_url


# =========================
# ROOT
# =========================

@app.get("/", response_class=HTMLResponse)
async def home():
    return html_page(
        "Lozo Gateway",
        """
        <h1>Lozo Gateway</h1>
        <p>
            Gateway is online.
        </p>
        """
    )


# =========================
# GATEWAY START
# =========================

@app.get("/api/gateway")
async def gateway(
    request: Request,
    token: str = Query(default="")
):

    if not token:
        return error_page(
            "Missing gateway token."
        )

    # -------------------------
    # Find original token
    # -------------------------

    try:
        result = (
            supabase
            .table("tokens")
            .select("*")
            .eq("token", token)
            .limit(1)
            .execute()
        )
    except Exception as e:
        return error_page(
            f"Database error: {str(e)}"
        )

    if not result.data:
        return error_page(
            "Invalid or expired token."
        )

    token_row = result.data[0]

    if token_row.get("used") is True:
        return error_page(
            "This link has already been used."
        )

    # -------------------------
    # Check token expiry
    # -------------------------

    expires_at = token_row.get("expires_at")

    if expires_at:
        try:
            expiry = datetime.fromisoformat(
                expires_at.replace("Z", "+00:00")
            )

            if expiry <= now_utc():
                return error_page(
                    "This link has expired."
                )

        except Exception:
            pass

    # -------------------------
    # Generate browser ID
    # -------------------------

    browser_id = request.cookies.get(
        BROWSER_COOKIE
    )

    if not browser_id:
        browser_id = secrets.token_urlsafe(32)

    browser_hash = sha256(browser_id)

    # -------------------------
    # Generate state
    # -------------------------

    state = secrets.token_urlsafe(32)

    expires = now_utc() + timedelta(
        minutes=STATE_TTL_MINUTES
    )

    # -------------------------
    # Save gateway state
    # -------------------------

    try:

        supabase.table("gateway_states").insert({
            "state": state,
            "token": token,
            "expires_at": expires.isoformat(),
            "used": False,
            "verified": False,
            "browser_hash": browser_hash
        }).execute()

    except Exception as e:
        return error_page(
            f"Unable to create secure session: {str(e)}"
        )

    # -------------------------
    # VPLink destination
    # -------------------------

    complete_url = (
        f"{GATEWAY_DOMAIN}"
        f"/api/complete?state={quote(state)}"
    )

    try:
        vp_url = create_vplink(
            complete_url
        )
    except Exception as e:
        return error_page(
            f"Unable to create shortener link: {str(e)}"
        )

    # -------------------------
    # Redirect to VPLink
    # -------------------------

    response = RedirectResponse(
        url=vp_url,
        status_code=302
    )

    response.set_cookie(
        key=BROWSER_COOKIE,
        value=browser_id,
        max_age=86400,
        httponly=True,
        samesite="lax",
        secure=True
    )

    return response


# =========================
# VP LINK COMPLETE
# =========================

@app.get("/api/complete")
async def complete(
    request: Request,
    state: str = Query(default="")
):

    if not state:
        return error_page(
            "Invalid completion request."
        )

    # -------------------------
    # Find state
    # -------------------------

    try:
        result = (
            supabase
            .table("gateway_states")
            .select("*")
            .eq("state", state)
            .limit(1)
            .execute()
        )
    except Exception as e:
        return error_page(
            f"Database error: {str(e)}"
        )

    if not result.data:
        return error_page(
            "This gateway session does not exist."
        )

    row = result.data[0]

    # -------------------------
    # Check state expiry
    # -------------------------

    expires_at = row.get("expires_at")

    if expires_at:
        try:
            expiry = datetime.fromisoformat(
                expires_at.replace("Z", "+00:00")
            )

            if expiry <= now_utc():
                return error_page(
                    "This gateway session has expired."
                )

        except Exception:
            pass

    # -------------------------
    # Browser binding
    # -------------------------

    browser_id = request.cookies.get(
        BROWSER_COOKIE
    )

    if not browser_id:
        return error_page(
            """
            Browser identity missing.<br><br>
            Go back to the bot and open the link again
            using the same browser.
            """
        )

    current_browser_hash = sha256(
        browser_id
    )

    saved_browser_hash = row.get(
        "browser_hash"
    )

    if (
        saved_browser_hash
        and current_browser_hash != saved_browser_hash
    ):
        return error_page(
            """
            <b>VERIFICATION FAILED</b><br><br>
            Browser identity mismatch.<br><br>
            This link was started on another browser
            or device. Go back to the bot and tap the
            button again using the same browser.
            """
        )

    # -------------------------
    # Already verified?
    # -------------------------

    if row.get("verified") is True:

        verified_until = row.get(
            "verify_expires_at"
        )

        if verified_until:

            try:
                verified_expiry = datetime.fromisoformat(
                    verified_until.replace("Z", "+00:00")
                )

                if verified_expiry > now_utc():

                    return deliver(
                        request,
                        row
                    )

            except Exception:
                pass

    # -------------------------
    # Create verification challenge
    # -------------------------

    challenge = secrets.token_urlsafe(32)

    challenge_hash = sha256(
        challenge
    )

    verify_expires = (
        now_utc()
        + timedelta(minutes=VERIFY_TTL_MINUTES)
    )

    try:

        supabase.table("gateway_states").update({
            "challenge_hash": challenge_hash,
            "verified": False,
            "verify_expires_at": verify_expires.isoformat()
        }).eq(
            "state",
            state
        ).execute()

    except Exception as e:
        return error_page(
            f"Unable to create verification session: {str(e)}"
        )

    # -------------------------
    # Manual verification page
    # -------------------------

    verify_url = (
        f"{GATEWAY_DOMAIN}"
        f"/verify/{quote(state)}"
        f"?challenge={quote(challenge)}"
    )

    return RedirectResponse(
        url=verify_url,
        status_code=302
    )


# =========================
# VERIFY
# =========================

@app.get(
    "/verify/{state}",
    response_class=HTMLResponse
)
async def verify(
    request: Request,
    state: str,
    challenge: str = Query(default="")
):

    if not state or not challenge:
        return error_page(
            "Invalid verification request."
        )

    # -------------------------
    # Load state
    # -------------------------

    try:

        result = (
            supabase
            .table("gateway_states")
            .select("*")
            .eq("state", state)
            .limit(1)
            .execute()
        )

    except Exception as e:
        return error_page(
            f"Database error: {str(e)}"
        )

    if not result.data:
        return error_page(
            "Verification session not found."
        )

    row = result.data[0]

    # -------------------------
    # Browser binding
    # -------------------------

    browser_id = request.cookies.get(
        BROWSER_COOKIE
    )

    if not browser_id:
        return error_page(
            """
            <b>VERIFICATION FAILED</b><br><br>
            Browser identity missing.
            """
        )

    current_browser_hash = sha256(
        browser_id
    )

    if (
        row.get("browser_hash")
        and current_browser_hash
        != row.get("browser_hash")
    ):
        return error_page(
            """
            <b>VERIFICATION FAILED</b><br><br>
            Browser identity mismatch.<br><br>
            This link was started on another browser
            or device.
            """
        )

    # -------------------------
    # Verify challenge
    # -------------------------

    if sha256(challenge) != row.get(
        "challenge_hash"
    ):
        return error_page(
            """
            <b>VERIFICATION FAILED</b><br><br>
            Invalid verification challenge.
            """
        )

    # -------------------------
    # Check verification expiry
    # -------------------------

    verify_expires = row.get(
        "verify_expires_at"
    )

    if verify_expires:

        try:

            expiry = datetime.fromisoformat(
                verify_expires.replace(
                    "Z",
                    "+00:00"
                )
            )

            if expiry <= now_utc():
                return error_page(
                    "Verification session expired. Please start again."
                )

        except Exception:
            pass

    # -------------------------
    # Mark verified
    # -------------------------

    verified_until = (
        now_utc()
        + timedelta(minutes=VERIFY_TTL_MINUTES)
    )

    try:

        supabase.table(
            "gateway_states"
        ).update({
            "verified": True,
            "verified_at": iso_now(),
            "verify_expires_at":
                verified_until.isoformat()
        }).eq(
            "state",
            state
        ).execute()

    except Exception as e:
        return error_page(
            f"Unable to save verification: {str(e)}"
        )

    # -------------------------
    # Redirect to complete
    # -------------------------

    complete_url = (
        f"{GATEWAY_DOMAIN}"
        f"/api/complete?state={quote(state)}"
    )

    response = RedirectResponse(
        url=complete_url,
        status_code=302
    )

    response.set_cookie(
        key=VERIFIED_COOKIE,
        value=sha256(
            state + "|" + browser_id
        ),
        max_age=VERIFY_TTL_MINUTES * 60,
        httponly=True,
        samesite="lax",
        secure=True
    )

    return response


# =========================
# FINAL DELIVERY
# =========================

def deliver(
    request: Request,
    row: dict
):

    state = row.get("state")
    token = row.get("token")

    if not state or not token:
        return error_page(
            "Invalid gateway state."
        )

    # -------------------------
    # Browser check
    # -------------------------

    browser_id = request.cookies.get(
        BROWSER_COOKIE
    )

    if not browser_id:
        return error_page(
            "Browser session missing."
        )

    browser_hash = sha256(
        browser_id
    )

    if (
        row.get("browser_hash")
        and browser_hash != row.get("browser_hash")
    ):
        return error_page(
            """
            <b>VERIFICATION FAILED</b><br><br>
            Browser identity mismatch.
            """
        )

    # -------------------------
    # Verified check
    # -------------------------

    if row.get("verified") is not True:
        return error_page(
            "Verification required."
        )

    # -------------------------
    # Verification expiry
    # -------------------------

    verify_expires = row.get(
        "verify_expires_at"
    )

    if verify_expires:

        try:

            expiry = datetime.fromisoformat(
                verify_expires.replace(
                    "Z",
                    "+00:00"
                )
            )

            if expiry <= now_utc():
                return error_page(
                    "Verification expired."
                )

        except Exception:
            pass

    # -------------------------
    # Original token
    # -------------------------

    try:

        result = (
            supabase
            .table("tokens")
            .select("*")
            .eq("token", token)
            .limit(1)
            .execute()
        )

    except Exception as e:
        return error_page(
            f"Database error: {str(e)}"
        )

    if not result.data:
        return error_page(
            "Original file token was not found."
        )

    token_row = result.data[0]

    # -------------------------
    # Check original token
    # -------------------------

    if token_row.get("used") is True:
        return error_page(
            "This file link has already been used."
        )

    expires_at = token_row.get(
        "expires_at"
    )

    if expires_at:

        try:

            expiry = datetime.fromisoformat(
                expires_at.replace(
                    "Z",
                    "+00:00"
                )
            )

            if expiry <= now_utc():
                return error_page(
                    "This file link has expired."
                )

        except Exception:
            pass

    # -------------------------
    # Telegram target
    # -------------------------

    target = token_row.get(
        "target"
    )

    if not target:
        return error_page(
            "Telegram destination is missing."
        )

    # -------------------------
    # Mark gateway state used
    #
    # IMPORTANT:
    # We DO NOT mark original
    # Telegram token as used here.
    # The Telegram bot should do that
    # when verify_TOKEN is actually
    # consumed.
    # -------------------------

    try:

        supabase.table(
            "gateway_states"
        ).update({
            "used": True
        }).eq(
            "state",
            state
        ).execute()

    except Exception:
        pass

    # -------------------------
    # Redirect to Telegram
    # -------------------------

    response = RedirectResponse(
        url=target,
        status_code=302
    )

    response.delete_cookie(
        VERIFIED_COOKIE
    )

    return response


# =========================
# HEALTH CHECK
# =========================

@app.get("/health")
async def health():
    return {
        "ok": True,
        "service": "lozo-gateway"
}
