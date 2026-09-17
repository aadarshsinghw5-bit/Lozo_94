import os
import secrets
import hashlib
import html
from datetime import datetime, timezone, timedelta
from urllib.parse import urlencode

import requests
from fastapi import FastAPI, Request, Query
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from supabase import create_client, Client


# ============================================================
# LOZO-94 GATEWAY
# Nazki-style:
# ACCESS -> VPLINK -> COMPLETE -> VERIFY -> TELEGRAM
# ============================================================

app = FastAPI(title="Lozo Gateway")


# ============================================================
# ENVIRONMENT VARIABLES
# ============================================================

SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_SERVICE_ROLE_KEY = os.getenv(
    "SUPABASE_SERVICE_ROLE_KEY", ""
).strip()

BOT_USERNAME = os.getenv("BOT_USERNAME", "").strip().lstrip("@")

VPLINK_API_URL = os.getenv(
    "VPLINK_API_URL",
    "https://vplink.in/api"
).strip().rstrip("/")

VPLINK_API_KEY = os.getenv("VPLINK_API_KEY", "").strip()

GATEWAY_DOMAIN = os.getenv(
    "GATEWAY_DOMAIN",
    "https://lozo-94.vercel.app"
).strip().rstrip("/")

SESSION_MINUTES = int(
    os.getenv("SESSION_MINUTES", "30")
)

VERIFY_MINUTES = int(
    os.getenv("VERIFY_MINUTES", "10")
)


# ============================================================
# SUPABASE
# ============================================================

supabase: Client | None = None

if SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY:
    supabase = create_client(
        SUPABASE_URL,
        SUPABASE_SERVICE_ROLE_KEY
    )


# ============================================================
# BASIC HELPERS
# ============================================================

def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def random_id(length: int = 32) -> str:
    return secrets.token_urlsafe(length)


def sha256(value: str) -> str:
    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


def db_ready() -> bool:
    return supabase is not None


def error_page(
    title: str,
    message: str,
    status_code: int = 400
):
    content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport"
              content="width=device-width,initial-scale=1">
        <title>{html.escape(title)}</title>
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
                background: #0b0b0f;
                color: #fff;
                font-family: Arial, sans-serif;
            }}

            .box {{
                width: 100%;
                max-width: 460px;
                padding: 30px 24px;
                border-radius: 18px;
                background: #15151c;
                border: 1px solid #292936;
                text-align: center;
                box-shadow: 0 15px 50px rgba(0,0,0,.45);
            }}

            h1 {{
                margin: 0 0 12px;
                font-size: 24px;
            }}

            p {{
                margin: 0;
                color: #bdbdc8;
                line-height: 1.6;
            }}
        </style>
    </head>
    <body>
        <div class="box">
            <h1>{html.escape(title)}</h1>
            <p>{html.escape(message)}</p>
        </div>
    </body>
    </html>
    """

    return HTMLResponse(
        content=content,
        status_code=status_code
    )


# ============================================================
# DATETIME HELPERS
# ============================================================

def parse_datetime(value):
    if not value:
        return None

    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(
                str(value).replace("Z", "+00:00")
            )
        except Exception:
            return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.astimezone(timezone.utc)


def is_expired(value) -> bool:
    dt = parse_datetime(value)

    if dt is None:
        return False

    return dt <= now_utc()


# ============================================================
# TOKEN DATABASE
# ============================================================

def get_token_record(token: str):
    if not db_ready():
        return None

    try:
        response = (
            supabase
            .table("tokens")
            .select("*")
            .eq("token", token)
            .limit(1)
            .execute()
        )

        if response.data:
            return response.data[0]

    except Exception:
        pass

    return None


# ============================================================
# GATEWAY STATE DATABASE
# ============================================================

def get_session(state: str):
    if not db_ready():
        return None

    try:
        response = (
            supabase
            .table("gateway_states")
            .select("*")
            .eq("state", state)
            .limit(1)
            .execute()
        )

        if response.data:
            return response.data[0]

    except Exception:
        pass

    return None


def get_session_by_verify_id(verify_id: str):
    if not db_ready():
        return None

    verify_hash = sha256(verify_id)

    try:
        response = (
            supabase
            .table("gateway_states")
            .select("*")
            .eq("challenge_hash", verify_hash)
            .limit(1)
            .execute()
        )

        if response.data:
            return response.data[0]

    except Exception:
        pass

    return None


def save_session(
    state: str,
    token: str,
    expires_at: datetime,
    browser_hash: str
):
    if not db_ready():
        return False

    try:
        supabase.table("gateway_states").insert({
            "state": state,
            "token": token,
            "expires_at": iso(expires_at),
            "used": False,
            "challenge_hash": None,
            "verified": False,
            "verified_at": None,
            "verify_expires_at": None,
            "browser_hash": browser_hash,
        }).execute()

        return True

    except Exception:
        return False


def update_session(
    state: str,
    values: dict
):
    if not db_ready():
        return False

    try:
        (
            supabase
            .table("gateway_states")
            .update(values)
            .eq("state", state)
            .execute()
        )

        return True

    except Exception:
        return False


def delete_session(state: str):
    if not db_ready():
        return False

    try:
        (
            supabase
            .table("gateway_states")
            .delete()
            .eq("state", state)
            .execute()
        )

        return True

    except Exception:
        return False


# ============================================================
# BROWSER ACCESS COOKIE
# ============================================================

ACCESS_COOKIE = "lozo_access"
VERIFY_COOKIE = "lozo_verified"


def browser_access_hash(request: Request):
    value = request.cookies.get(ACCESS_COOKIE)

    if not value:
        return None

    return sha256(value)


def verify_cookie_value(state: str) -> str:
    return sha256(state)


# ============================================================
# VPLINK API
# ============================================================

def create_vplink(destination: str):
    """
    Tries common VPLink API formats.

    Expected environment:
        VPLINK_API_URL
        VPLINK_API_KEY
    """

    if not VPLINK_API_KEY:
        raise RuntimeError(
            "VPLINK_API_KEY is not configured."
        )

    endpoint = VPLINK_API_URL

    query_variants = [
        {
            "api": VPLINK_API_KEY,
            "url": destination
        },
        {
            "api_key": VPLINK_API_KEY,
            "url": destination
        },
        {
            "key": VPLINK_API_KEY,
            "url": destination
        },
        {
            "api": VPLINK_API_KEY,
            "link": destination
        },
        {
            "api_key": VPLINK_API_KEY,
            "link": destination
        },
    ]

    headers_variants = [
        {},
        {
            "Authorization":
                f"Bearer {VPLINK_API_KEY}"
        },
    ]

    last_error = None

    for params in query_variants:
        for headers in headers_variants:
            try:
                response = requests.get(
                    endpoint,
                    params={
                        **params,
                        "url": destination
                    },
                    headers=headers,
                    timeout=15
                )

                if not response.ok:
                    last_error = (
                        f"HTTP {response.status_code}"
                    )
                    continue

                try:
                    data = response.json()
                except Exception:
                    data = None

                if isinstance(data, str):
                    if data.startswith("http"):
                        return data

                if isinstance(data, dict):

                    possible_values = [
                        data.get("shortenedUrl"),
                        data.get("short_url"),
                        data.get("shorturl"),
                        data.get("url"),
                        data.get("link"),
                        data.get("shortened"),
                        data.get("result"),
                    ]

                    nested = data.get("data")

                    if isinstance(nested, dict):
                        possible_values.extend([
                            nested.get("shortenedUrl"),
                            nested.get("short_url"),
                            nested.get("shorturl"),
                            nested.get("url"),
                            nested.get("link"),
                        ])

                    for value in possible_values:
                        if isinstance(value, str):
                            if value.startswith("http"):
                                return value

                text = response.text.strip()

                if text.startswith("http"):
                    return text

            except Exception as exc:
                last_error = str(exc)

    raise RuntimeError(
        f"Unable to create VPLink: {last_error}"
    )


# ============================================================
# HTML - ACCESS PAGE
# ============================================================

def access_page(vplink_url: str):
    safe_url = html.escape(
        vplink_url,
        quote=True
    )

    content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport"
              content="width=device-width,initial-scale=1">

        <meta http-equiv="refresh"
              content="1;url={safe_url}">

        <title>Secure Access</title>

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
                background:
                    radial-gradient(
                        circle at top,
                        #24243a,
                        #09090d 60%
                    );
                color: white;
                font-family: Arial, sans-serif;
            }}

            .box {{
                width: 100%;
                max-width: 440px;
                text-align: center;
                padding: 32px 24px;
                border-radius: 22px;
                background: rgba(20,20,28,.94);
                border: 1px solid #30303d;
                box-shadow: 0 20px 60px rgba(0,0,0,.5);
            }}

            .loader {{
                width: 48px;
                height: 48px;
                margin: 0 auto 20px;
                border: 4px solid #353542;
                border-top-color: white;
                border-radius: 50%;
                animation: spin 1s linear infinite;
            }}

            @keyframes spin {{
                to {{
                    transform: rotate(360deg);
                }}
            }}

            h1 {{
                margin: 0 0 10px;
                font-size: 23px;
            }}

            p {{
                margin: 0 0 22px;
                color: #aaaab7;
                line-height: 1.5;
            }}

            a {{
                display: inline-block;
                padding: 12px 22px;
                border-radius: 12px;
                background: white;
                color: black;
                text-decoration: none;
                font-weight: 700;
            }}
        </style>
    </head>

    <body>
        <div class="box">
            <div class="loader"></div>

            <h1>Initializing secure session...</h1>

            <p>
                Please wait while your secure access
                session is being prepared.
            </p>

            <a href="{safe_url}">
                Continue
            </a>
        </div>
    </body>
    </html>
    """

    return HTMLResponse(content=content)


# ============================================================
# HTML - VERIFY PAGE
# ============================================================

def verification_page(
    verify_id: str,
    remaining_seconds: int
):
    safe_verify_id = html.escape(
        verify_id,
        quote=True
    )

    seconds = max(1, remaining_seconds)

    content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">

        <meta name="viewport"
              content="width=device-width,initial-scale=1">

        <title>Verification Required</title>

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

                background:
                    radial-gradient(
                        circle at top,
                        #24243a,
                        #08080c 65%
                    );

                color: white;
                font-family: Arial, sans-serif;
            }}

            .card {{
                width: 100%;
                max-width: 470px;
                padding: 30px 24px;
                border-radius: 22px;

                background: rgba(20,20,28,.97);
                border: 1px solid #30303c;

                box-shadow:
                    0 25px 70px rgba(0,0,0,.55);
            }}

            h1 {{
                margin: 0 0 12px;
                font-size: 25px;
                text-align: center;
            }}

            .sub {{
                margin: 0 0 25px;
                color: #a8a8b5;
                line-height: 1.55;
                text-align: center;
            }}

            .check {{
                display: flex;
                align-items: center;
                gap: 13px;

                padding: 17px;
                margin-bottom: 18px;

                border-radius: 14px;
                background: #111118;
                border: 1px solid #30303c;

                cursor: pointer;
                user-select: none;
            }}

            .check input {{
                width: 22px;
                height: 22px;
                cursor: pointer;
            }}

            .check span {{
                color: #dedee7;
                line-height: 1.4;
            }}

            button {{
                width: 100%;
                padding: 14px;
                border: 0;
                border-radius: 13px;

                background: white;
                color: black;

                font-size: 16px;
                font-weight: 700;

                cursor: pointer;
            }}

            button:disabled {{
                opacity: .45;
                cursor: not-allowed;
            }}

            .timer {{
                margin-top: 17px;
                text-align: center;
                color: #777785;
                font-size: 13px;
            }}

            .notice {{
                margin-top: 20px;
                padding: 13px;

                border-radius: 12px;

                background: #181820;
                color: #858592;

                font-size: 12px;
                line-height: 1.5;
                text-align: center;
            }}
        </style>
    </head>

    <body>
        <div class="card">

            <h1>Human Verification</h1>

            <p class="sub">
                Your secure session is ready.
                Complete the verification below to continue.
            </p>

            <label class="check">
                <input
                    id="human"
                    type="checkbox"
                    onchange="toggleButton()"
                >

                <span>
                    I am a human and I want to continue
                </span>
            </label>

            <button
                id="continueBtn"
                disabled
                onclick="continueVerification()"
            >
                Continue
            </button>

            <div class="timer">
                Verification expires in
                <span id="timer">{seconds}</span>s
            </div>

            <div class="notice">
                This verification session is temporary and
                can only be used once.
            </div>

        </div>

        <script>
            let remaining = {seconds};

            function toggleButton() {{
                const checked =
                    document.getElementById("human").checked;

                document.getElementById(
                    "continueBtn"
                ).disabled = !checked;
            }}

            function continueVerification() {{
                const checked =
                    document.getElementById("human").checked;

                if (!checked) {{
                    return;
                }}

                const button =
                    document.getElementById("continueBtn");

                button.disabled = true;
                button.innerText = "Verifying...";

                setTimeout(function() {{
                    window.location.href =
                        "/verify/{safe_verify_id}";
                }}, 900);
            }}

            const interval = setInterval(function() {{
                remaining--;

                document.getElementById(
                    "timer"
                ).innerText = Math.max(0, remaining);

                if (remaining <= 0) {{
                    clearInterval(interval);

                    const button =
                        document.getElementById(
                            "continueBtn"
                        );

                    button.disabled = true;
                    button.innerText = "Session Expired";
                }}
            }}, 1000);
        </script>

    </body>
    </html>
    """

    return HTMLResponse(content=content)


# ============================================================
# ROOT
# ============================================================

@app.get("/")
async def root():
    return JSONResponse({
        "ok": True,
        "service": "lozo-gateway"
    })


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
async def health():
    return JSONResponse({
        "ok": True
    })


# ============================================================
# ACCESS ENTRY
#
# /api/gateway?token=XXXX
#
# This creates the hidden session and redirects to:
#
# /access/<random-access-id>
# ============================================================

@app.get("/api/gateway")
async def gateway(
    request: Request,
    token: str = Query(...)
):
    token = token.strip()

    if not token:
        return error_page(
            "Invalid Request",
            "Missing access token."
        )

    if not db_ready():
        return error_page(
            "Gateway Error",
            "Database is not configured.",
            500
        )

    if not BOT_USERNAME:
        return error_page(
            "Gateway Error",
            "BOT_USERNAME is not configured.",
            500
        )

    record = get_token_record(token)

    if not record:
        return error_page(
            "Invalid Link",
            "This shortener link is invalid or expired."
        )

    if record.get("expires_at"):
        if is_expired(record.get("expires_at")):
            return error_page(
                "Link Expired",
                "This shortener link has expired."
            )

    # --------------------------------------------------------
    # Random access ID
    # --------------------------------------------------------

    access_id = random_id(24)

    # Browser-bound random value
    browser_id = random_id(32)

    browser_hash = sha256(browser_id)

    expires_at = (
        now_utc()
        + timedelta(minutes=SESSION_MINUTES)
    )

    saved = save_session(
        state=access_id,
        token=token,
        expires_at=expires_at,
        browser_hash=browser_hash
    )

    if not saved:
        return error_page(
            "Gateway Error",
            "Unable to create secure session.",
            500
        )

    # --------------------------------------------------------
    # VPLink destination
    #
    # VPLink will eventually redirect here.
    # Original Telegram token is NOT put here.
    # --------------------------------------------------------

    complete_url = (
        f"{GATEWAY_DOMAIN}/api/complete?"
        + urlencode({
            "state": access_id
        })
    )

    try:
        vplink_url = create_vplink(
            complete_url
        )
    except Exception as exc:
        delete_session(access_id)

        return error_page(
            "VPLink Error",
            str(exc),
            500
        )

    # --------------------------------------------------------
    # Redirect to clean /access/<id>
    # --------------------------------------------------------

    response = RedirectResponse(
        url=f"/access/{access_id}",
        status_code=302
    )

    # Secure session cookie.
    #
    # This cookie is required when VPLink comes back.
    #
    response.set_cookie(
        key=ACCESS_COOKIE,
        value=browser_id,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
        max_age=SESSION_MINUTES * 60
    )

    # Save VPLink destination nowhere public.
    #
    # Instead of exposing it in the database, return it through
    # an internal temporary route.
    #
    # We use a response cookie to carry it only inside this
    # browser session.
    response.set_cookie(
        key="lozo_vplink",
        value=secrets.token_urlsafe(18),
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
        max_age=SESSION_MINUTES * 60
    )

    # Store VPLink URL in target field of this gateway session.
    #
    # The original tokens.target remains untouched.
    update_session(
        access_id,
        {
            "target": vplink_url
        }
    )

    return response


# ============================================================
# ACCESS PAGE
#
# /access/<access_id>
# ============================================================

@app.get("/access/{access_id}")
async def access(
    request: Request,
    access_id: str
):
    session = get_session(access_id)

    if not session:
        return error_page(
            "Invalid Session",
            "This secure access session does not exist."
        )

    if session.get("used"):
        return error_page(
            "Session Used",
            "This session has already been used."
        )

    if is_expired(session.get("expires_at")):
        return error_page(
            "Session Expired",
            "This secure access session has expired."
        )

    # Browser cookie must exist.
    browser_value = request.cookies.get(
        ACCESS_COOKIE
    )

    if not browser_value:
        return error_page(
            "Session Missing",
            "Please open the original access link again."
        )

    stored_browser_hash = session.get(
        "browser_hash"
    )

    if stored_browser_hash:
        if sha256(browser_value) != stored_browser_hash:
            return error_page(
                "Session Mismatch",
                "This access session belongs to another browser."
            )

    vplink_url = session.get("target")

    if not vplink_url:
        return error_page(
            "Gateway Error",
            "VPLink destination is missing.",
            500
        )

    return access_page(vplink_url)


# ============================================================
# COMPLETE
#
# VPLink should redirect to:
#
# /api/complete?state=<access_id>
#
# This endpoint DOES NOT directly deliver Telegram.
#
# It creates a completely different random verify ID.
# ============================================================

@app.get("/api/complete")
async def complete(
    request: Request,
    state: str = Query("")
):
    state = state.strip()

    if not state:
        return error_page(
            "Invalid Completion",
            "Please manually verify. Don't try to bypass."
        )

    session = get_session(state)

    if not session:
        return error_page(
            "Invalid Session",
            "This completion session is invalid."
        )

    if session.get("used"):
        return error_page(
            "Session Used",
            "This session has already been completed."
        )

    if is_expired(session.get("expires_at")):
        return error_page(
            "Session Expired",
            "This secure session has expired."
        )

    # --------------------------------------------------------
    # Browser binding
    # --------------------------------------------------------

    browser_value = request.cookies.get(
        ACCESS_COOKIE
    )

    stored_browser_hash = session.get(
        "browser_hash"
    )

    if not browser_value:
        return error_page(
            "Verification Required",
            "Open this link from the same browser session."
        )

    if stored_browser_hash:
        if sha256(browser_value) != stored_browser_hash:
            return error_page(
                "Session Mismatch",
                "This session belongs to another                browser session."
            )

    # ========================================================
    # ALREADY VERIFIED?
    # ========================================================
    #
    # A verified session still requires the verification
    # cookie. This prevents someone who only knows the state
    # from directly obtaining the Telegram link.
    # ========================================================

    if session.get("verified"):
        verified_cookie = request.cookies.get(
            VERIFY_COOKIE
        )

        expected_cookie = verify_cookie_value(state)

        if verified_cookie != expected_cookie:
            # Verification cookie is missing.
            # Reset verification and create a fresh verify ID.

            verify_id = random_id(32)

            update_session(
                state,
                {
                    "verified": False,
                    "verified_at": None,
                    "verify_expires_at": None,
                    "challenge_hash": sha256(verify_id),
                }
            )

            response = verification_page(
                verify_id,
                VERIFY_MINUTES * 60
            )

            return response

        verify_expiry = parse_datetime(
            session.get("verify_expires_at")
        )

        if (
            verify_expiry is None
            or verify_expiry <= now_utc()
        ):
            # Verification expired.
            # Force a new verification cycle.

            verify_id = random_id(32)

            update_session(
                state,
                {
                    "verified": False,
                    "verified_at": None,
                    "verify_expires_at": None,
                    "challenge_hash": sha256(verify_id),
                }
            )

            response = verification_page(
                verify_id,
                VERIFY_MINUTES * 60
            )

            return response

        # Valid verified session.
        # Continue to final delivery endpoint.

        return RedirectResponse(
            url=f"/api/deliver?state={state}",
            status_code=302
        )

    # ========================================================
    # CREATE NEW VERIFY ID
    # ========================================================

    verify_id = random_id(32)

    verify_expiry = (
        now_utc()
        + timedelta(minutes=VERIFY_MINUTES)
    )

    updated = update_session(
        state,
        {
            "challenge_hash": sha256(verify_id),
            "verified": False,
            "verified_at": None,
            "verify_expires_at": iso(
                verify_expiry
            ),
        }
    )

    if not updated:
        return error_page(
            "Gateway Error",
            "Unable to create verification session.",
            500
        )

    # ========================================================
    # VERIFICATION PAGE
    # ========================================================

    return verification_page(
        verify_id,
        VERIFY_MINUTES * 60
    )


# ============================================================
# VERIFY
#
# /verify/<verify_id>
#
# The verify ID is different from the access ID.
# ============================================================

@app.get("/verify/{verify_id}")
async def verify(
    request: Request,
    verify_id: str
):
    verify_id = verify_id.strip()

    if not verify_id:
        return error_page(
            "Invalid Verification",
            "Verification ID is missing."
        )

    session = get_session_by_verify_id(
        verify_id
    )

    if not session:
        return error_page(
            "Invalid Verification",
            "This verification session is invalid or expired."
        )

    state = session.get("state")

    if not state:
        return error_page(
            "Invalid Session",
            "Gateway session is invalid."
        )

    if session.get("used"):
        return error_page(
            "Session Used",
            "This session has already been used."
        )

    if is_expired(
        session.get("expires_at")
    ):
        return error_page(
            "Session Expired",
            "This secure session has expired."
        )

    # ========================================================
    # BROWSER BINDING
    # ========================================================

    browser_value = request.cookies.get(
        ACCESS_COOKIE
    )

    if not browser_value:
        return error_page(
            "Browser Session Missing",
            "Please start the original link again."
        )

    stored_browser_hash = session.get(
        "browser_hash"
    )

    if (
        stored_browser_hash
        and sha256(browser_value)
        != stored_browser_hash
    ):
        return error_page(
            "Browser Mismatch",
            "This verification belongs to another browser."
        )

    # ========================================================
    # VERIFY ID CHECK
    # ========================================================

    stored_verify_hash = session.get(
        "challenge_hash"
    )

    if not stored_verify_hash:
        return error_page(
            "Invalid Verification",
            "Verification challenge is missing."
        )

    if sha256(verify_id) != stored_verify_hash:
        return error_page(
            "Invalid Verification",
            "This verification link is invalid."
        )

    # ========================================================
    # VERIFICATION EXPIRY
    # ========================================================

    verify_expiry = parse_datetime(
        session.get("verify_expires_at")
    )

    if (
        verify_expiry is None
        or verify_expiry <= now_utc()
    ):
        return error_page(
            "Verification Expired",
            "Please start the access process again."
        )

    # ========================================================
    # MARK VERIFIED
    # ========================================================

    verified_at = now_utc()

    updated = update_session(
        state,
        {
            "verified": True,
            "verified_at": iso(verified_at),
            "verify_expires_at": iso(
                verify_expiry
            ),
        }
    )

    if not updated:
        return error_page(
            "Gateway Error",
            "Unable to complete verification.",
            500
        )

    # ========================================================
    # CREATE VERIFICATION COOKIE
    # ========================================================

    response = RedirectResponse(
        url=f"/api/deliver?state={state}",
        status_code=302
    )

    response.set_cookie(
        key=VERIFY_COOKIE,
        value=verify_cookie_value(state),
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
        max_age=VERIFY_MINUTES * 60
    )

    return response


# ============================================================
# FINAL DELIVERY
#
# IMPORTANT:
# Gateway itself does NOT send the file.
#
# It only generates:
#
# https://t.me/BOT_USERNAME?start=verify_TOKEN
#
# Your Telegram bot handles the actual file delivery.
# ============================================================

@app.get("/api/deliver")
async def deliver(
    request: Request,
    state: str = Query("")
):
    state = state.strip()

    if not state:
        return error_page(
            "Invalid Request",
            "Missing gateway state."
        )

    session = get_session(state)

    if not session:
        return error_page(
            "Invalid Session",
            "This gateway session does not exist."
        )

    if session.get("used"):
        return error_page(
            "Session Used",
            "This session has already been used."
        )

    if is_expired(
        session.get("expires_at")
    ):
        return error_page(
            "Session Expired",
            "This gateway session has expired."
        )

    # ========================================================
    # BROWSER BINDING
    # ========================================================

    browser_value = request.cookies.get(
        ACCESS_COOKIE
    )

    stored_browser_hash = session.get(
        "browser_hash"
    )

    if not browser_value:
        return error_page(
            "Browser Session Missing",
            "Please start the original access link again."
        )

    if (
        stored_browser_hash
        and sha256(browser_value)
        != stored_browser_hash
    ):
        return error_page(
            "Browser Mismatch",
            "This session belongs to another browser."
        )

    # ========================================================
    # VERIFIED CHECK
    # ========================================================

    if not session.get("verified"):
        return error_page(
            "Verification Required",
            "Please complete verification first."
        )

    # ========================================================
    # VERIFICATION COOKIE CHECK
    # ========================================================

    verified_cookie = request.cookies.get(
        VERIFY_COOKIE
    )

    expected_cookie = verify_cookie_value(
        state
    )

    if verified_cookie != expected_cookie:
        # Do NOT deliver.
        #
        # Create a fresh verification challenge.

        verify_id = random_id(32)

        verify_expiry = (
            now_utc()
            + timedelta(minutes=VERIFY_MINUTES)
        )

        update_session(
            state,
            {
                "verified": False,
                "verified_at": None,
                "verify_expires_at": iso(
                    verify_expiry
                ),
                "challenge_hash": sha256(
                    verify_id
                ),
            }
        )

        return verification_page(
            verify_id,
            VERIFY_MINUTES * 60
        )

    # ========================================================
    # VERIFY EXPIRY
    # ========================================================

    verify_expiry = parse_datetime(
        session.get("verify_expires_at")
    )

    if (
        verify_expiry is None
        or verify_expiry <= now_utc()
    ):
        verify_id = random_id(32)

        new_expiry = (
            now_utc()
            + timedelta(minutes=VERIFY_MINUTES)
        )

        update_session(
            state,
            {
                "verified": False,
                "verified_at": None,
                "verify_expires_at": iso(
                    new_expiry
                ),
                "challenge_hash": sha256(
                    verify_id
                ),
            }
        )

        return verification_page(
            verify_id,
            VERIFY_MINUTES * 60
        )

    # ========================================================
    # ORIGINAL TOKEN
    # ========================================================

    original_token = session.get(
        "token"
    )

    if not original_token:
        return error_page(
            "Gateway Error",
            "Original token is missing.",
            500
        )

    token_record = get_token_record(
        original_token
    )

    if not token_record:
        return error_page(
            "Invalid Link",
            "The original file link is invalid or expired."
        )

    if token_record.get("expires_at"):
        if is_expired(
            token_record.get("expires_at")
        ):
            return error_page(
                "Link Expired",
                "The original file link has expired."
            )

    # ========================================================
    # TELEGRAM DEEP LINK
    # ========================================================

    if not BOT_USERNAME:
        return error_page(
            "Gateway Error",
            "BOT_USERNAME is not configured.",
            500
        )

    telegram_url = (
        f"https://t.me/{BOT_USERNAME}"
        f"?start=verify_{original_token}"
    )

    # ========================================================
    # MARK GATEWAY SESSION USED
    #
    # IMPORTANT:
    # We DO NOT mark tokens.used=True here.
    #
    # Telegram bot must perform final token validation
    # and file delivery.
    # ========================================================

    update_session(
        state,
        {
            "used": True
        }
    )

    response = RedirectResponse(
        url=telegram_url,
        status_code=302
    )

    # Remove gateway cookies after successful handoff.

    response.delete_cookie(
        ACCESS_COOKIE,
        path="/"
    )

    response.delete_cookie(
        VERIFY_COOKIE,
        path="/"
    )

    return response


# ============================================================
# SESSION DIAGNOSTIC
#
# Safe diagnostic endpoint.
# Does NOT expose original token or target.
#
# /api/session?state=XXXX
# ============================================================

@app.get("/api/session")
async def session_info(
    state: str = Query("")
):
    state = state.strip()

    if not state:
        return JSONResponse(
            {
                "ok": False,
                "error": "Missing state"
            },
            status_code=400
        )

    session = get_session(state)

    if not session:
        return JSONResponse(
            {
                "ok": False,
                "exists": False
            },
            status_code=404
        )

    expires_at = parse_datetime(
        session.get("expires_at")
    )

    verify_expires_at = parse_datetime(
        session.get("verify_expires_at")
    )

    return JSONResponse({
        "ok": True,
        "exists": True,
        "expired": (
            expires_at is not None
            and expires_at <= now_utc()
        ),
        "verified": bool(
            session.get("verified")
        ),
        "used": bool(
            session.get("used")
        ),
        "verify_expired": (
            verify_expires_at is not None
            and verify_expires_at <= now_utc()
        )
    })


# ============================================================
# VERCEL / ASGI ENTRY
# ============================================================

# FastAPI's `app` object is automatically used by Vercel's
# Python runtime.
