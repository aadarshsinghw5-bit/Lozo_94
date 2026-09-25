import os
import secrets
import hashlib
import html
import logging
from datetime import datetime, timezone, timedelta
from urllib.parse import urlencode

import requests
from fastapi import FastAPI, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from pymongo import MongoClient, ASCENDING


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("lozo-gateway")


# ============================================================
# CONFIG
# ============================================================

MONGO_URI = os.getenv("MONGO_URI", "").strip()

MONGO_DB = (
    os.getenv("MONGO_DB", "file_store_bot").strip()
    or "file_store_bot"
)

BOT_USERNAME = (
    os.getenv("BOT_USERNAME", "").strip().lstrip("@")
)

VPLINK_API_URL = (
    os.getenv(
        "VPLINK_API_URL",
        "https://vplink.in/api"
    ).strip().rstrip("/")
)

VPLINK_API_KEY = (
    os.getenv("VPLINK_API_KEY", "").strip()
)

GATEWAY_DOMAIN = (
    os.getenv(
        "GATEWAY_DOMAIN",
        "https://lozo-94.vercel.app"
    ).strip().rstrip("/")
)

try:
    SESSION_MINUTES = int(
        os.getenv("SESSION_MINUTES", "30")
    )
except Exception:
    SESSION_MINUTES = 30

try:
    VERIFY_MINUTES = int(
        os.getenv("VERIFY_MINUTES", "10")
    )
except Exception:
    VERIFY_MINUTES = 10


# ============================================================
# APP / DATABASE
# ============================================================

app = FastAPI()

mongo = None
db = None


def initialize_database():
    """
    Connect to MongoDB and make sure required indexes exist.

    IMPORTANT:
    An old gateway_states.token_1 index may already exist as
    UNIQUE. The current gateway requires this index to be
    NON-UNIQUE, so we safely remove the conflicting old index.
    """

    global mongo, db

    if not MONGO_URI:
        logger.error("MONGO_URI is not configured.")
        return False

    try:
        mongo = MongoClient(
            MONGO_URI,
            serverSelectionTimeoutMS=10000,
            connectTimeoutMS=10000,
            socketTimeoutMS=10000,
        )

        # Force MongoDB connection test.
        mongo.admin.command("ping")

        db = mongo[MONGO_DB]

        # ----------------------------------------------------
        # TOKENS
        #
        # Original token itself should remain unique.
        # ----------------------------------------------------

        tokens_indexes = list(
            db.tokens.list_indexes()
        )

        token_index = next(
            (
                index
                for index in tokens_indexes
                if index.get("key") == {"token": 1}
            ),
            None
        )

        if token_index:
            if token_index.get("unique") is not True:
                db.tokens.drop_index(
                    token_index["name"]
                )

                db.tokens.create_index(
                    [("token", ASCENDING)],
                    name="token_1",
                    unique=True
                )
        else:
            db.tokens.create_index(
                [("token", ASCENDING)],
                name="token_1",
                unique=True
            )

        # ----------------------------------------------------
        # GATEWAY STATES
        #
        # state = unique
        # token = NON-unique
        # challenge_hash = unique/sparse
        # ----------------------------------------------------

        gateway_indexes = list(
            db.gateway_states.list_indexes()
        )

        # state index
        state_index = next(
            (
                index
                for index in gateway_indexes
                if index.get("key") == {"state": 1}
            ),
            None
        )

        if state_index:
            if state_index.get("unique") is not True:
                db.gateway_states.drop_index(
                    state_index["name"]
                )

                db.gateway_states.create_index(
                    [("state", ASCENDING)],
                    name="state_1",
                    unique=True
                )
        else:
            db.gateway_states.create_index(
                [("state", ASCENDING)],
                name="state_1",
                unique=True
            )

        # ----------------------------------------------------
        # TOKEN INDEX
        #
        # VERY IMPORTANT:
        # Old version may have created:
        #
        # token_1 -> unique=True
        #
        # Drop it and recreate as non-unique.
        # ----------------------------------------------------

        gateway_indexes = list(
            db.gateway_states.list_indexes()
        )

        token_state_index = next(
            (
                index
                for index in gateway_indexes
                if index.get("key") == {"token": 1}
            ),
            None
        )

        if token_state_index:

            if token_state_index.get("unique") is True:

                logger.warning(
                    "Removing old UNIQUE gateway_states token index: %s",
                    token_state_index["name"]
                )

                db.gateway_states.drop_index(
                    token_state_index["name"]
                )

                db.gateway_states.create_index(
                    [("token", ASCENDING)],
                    name="token_1",
                    unique=False
                )

            else:
                # Already correct.
                logger.info(
                    "gateway_states token index already non-unique."
                )

        else:
            db.gateway_states.create_index(
                [("token", ASCENDING)],
                name="token_1",
                unique=False
            )

        # ----------------------------------------------------
        # CHALLENGE HASH
        # ----------------------------------------------------

        gateway_indexes = list(
            db.gateway_states.list_indexes()
        )

        challenge_index = next(
            (
                index
                for index in gateway_indexes
                if index.get("key") == {"challenge_hash": 1}
            ),
            None
        )

        if challenge_index:
            if challenge_index.get("unique") is not True:

                db.gateway_states.drop_index(
                    challenge_index["name"]
                )

                db.gateway_states.create_index(
                    [("challenge_hash", ASCENDING)],
                    name="challenge_hash_1",
                    unique=True,
                    sparse=True
                )
        else:
            db.gateway_states.create_index(
                [("challenge_hash", ASCENDING)],
                name="challenge_hash_1",
                unique=True,
                sparse=True
            )

        logger.info(
            "MongoDB connected successfully: %s",
            MONGO_DB
        )

        logger.info(
            "MongoDB indexes verified successfully."
        )

        return True

    except Exception as e:

        logger.exception(
            "MongoDB initialization failed: %s",
            e
        )

        mongo = None
        db = None

        return False


initialize_database()


# ============================================================
# CONSTANTS
# ============================================================

ACCESS_COOKIE = "lozo_access"
VERIFY_COOKIE = "lozo_verified"
BROWSER_COOKIE = "lozo_browser_id"
VPLINK_COOKIE = "lozo_vplink"

EXPIRED_MESSAGE = (
    "This link has expired and can no longer be accessed. "
    "Please generate a new link from the channel to continue."
)


# ============================================================
# BASIC HELPERS
# ============================================================

def now_utc():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.astimezone(timezone.utc).isoformat()


def random_id(length=32):
    return secrets.token_urlsafe(length)


def sha256(value):
    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


def db_ready():
    return db is not None


def parse_datetime(value):

    if not value:
        return None

    try:

        if isinstance(value, datetime):
            dt = value

        else:
            dt = datetime.fromisoformat(
                str(value).replace(
                    "Z",
                    "+00:00"
                )
            )

        if dt.tzinfo is None:
            dt = dt.replace(
                tzinfo=timezone.utc
            )

        return dt.astimezone(
            timezone.utc
        )

    except Exception:
        return None


def is_expired(value):

    dt = parse_datetime(value)

    if dt is None:
        return True

    return dt <= now_utc()


# ============================================================
# ERROR PAGE
# ============================================================

def error_page(title, message):

    safe_title = html.escape(
        str(title)
    )

    safe_message = html.escape(
        str(message)
    )

    return HTMLResponse(
        f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport"
      content="width=device-width,initial-scale=1.0">
<title>{safe_title} - Lozo Gateway</title>

<style>
* {{
    box-sizing:border-box;
}}

body {{
    margin:0;
    min-height:100vh;
    display:flex;
    align-items:center;
    justify-content:center;
    padding:20px;
    background:linear-gradient(
        135deg,
        #020617,
        #111827,
        #0f172a
    );
    color:white;
    font-family:
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        Roboto,
        Arial,
        sans-serif;
}}

.card {{
    width:100%;
    max-width:460px;
    padding:34px 25px;
    text-align:center;
    background:rgba(255,255,255,.06);
    border:1px solid rgba(255,255,255,.10);
    border-radius:22px;
    box-shadow:0 20px 60px rgba(0,0,0,.45);
}}

.icon {{
    width:70px;
    height:70px;
    margin:0 auto 20px;
    display:flex;
    align-items:center;
    justify-content:center;
    border-radius:50%;
    background:rgba(239,68,68,.15);
    color:#f87171;
    font-size:32px;
    font-weight:700;
}}

h1 {{
    margin:0 0 12px;
    font-size:25px;
}}

p {{
    margin:0;
    color:#cbd5e1;
    line-height:1.6;
    font-size:14px;
}}

.brand {{
    margin-top:24px;
    color:#64748b;
    font-size:12px;
}}
</style>
</head>

<body>

<div class="card">

<div class="icon">!</div>

<h1>{safe_title}</h1>

<p>{safe_message}</p>

<div class="brand">
Lozo Gateway
</div>

</div>

</body>
</html>
""",
        status_code=400
    )


# ============================================================
# TOKEN HELPERS
# ============================================================

def get_token_record(token):

    if not db_ready():
        return None

    try:

        return db.tokens.find_one(
            {"token": token},
            {"_id": 0}
        )

    except Exception as e:

        logger.exception(
            "Failed to read token: %s",
            e
        )

        return None


def token_entry_used(token):

    if not db_ready():
        return False

    try:

        return (
            db.gateway_states.find_one(
                {
                    "token": token,
                    "entry_used": True
                },
                {"_id": 1}
            )
            is not None
        )

    except Exception as e:

        logger.exception(
            "Failed to check token entry state: %s",
            e
        )

        return False


# ============================================================
# SESSION HELPERS
# ============================================================

def get_session(state):

    if not db_ready():
        return None

    try:

        return db.gateway_states.find_one(
            {"state": state},
            {"_id": 0}
        )

    except Exception as e:

        logger.exception(
            "Failed to get session: %s",
            e
        )

        return None


def get_session_by_verify_id(verify_id):

    if not db_ready():
        return None

    try:

        return db.gateway_states.find_one(
            {
                "challenge_hash": sha256(
                    verify_id
                )
            },
            {"_id": 0}
        )

    except Exception as e:

        logger.exception(
            "Failed to get verification session: %s",
            e
        )

        return None


def save_session(
    state,
    token,
    expires_at,
    browser_hash
):

    if not db_ready():

        logger.error(
            "Cannot save session: database unavailable."
        )

        return False

    payload = {
        "state": state,
        "token": token,
        "expires_at": expires_at,
        "used": False,
        "entry_used": True,
        "challenge_hash": None,
        "verified": False,
        "verified_at": None,
        "verify_expires_at": None,
        "browser_hash": browser_hash,
    }

    try:

        db.gateway_states.insert_one(
            payload
        )

        logger.info(
            "Gateway session created: %s",
            state
        )

        return True

    except Exception as e:

        logger.exception(
            "Failed to save gateway session: %s",
            e
        )

        return False


def update_session(state, values):

    if not db_ready():
        return False

    try:

        result = db.gateway_states.update_one(
            {"state": state},
            {"$set": values}
        )

        return result.matched_count > 0

    except Exception as e:

        logger.exception(
            "Failed to update session: %s",
            e
        )

        return False


def delete_session(state):

    if not db_ready():
        return False

    try:

        db.gateway_states.delete_one(
            {"state": state}
        )

        return True

    except Exception as e:

        logger.exception(
            "Failed to delete session: %s",
            e
        )

        return False


# ============================================================
# VPLINK
# ============================================================

def create_vplink(destination):

    if not VPLINK_API_KEY:

        logger.error(
            "VPLINK_API_KEY is not configured."
        )

        return None

    endpoints = [
        VPLINK_API_URL,
        f"{VPLINK_API_URL}/shorten",
        f"{VPLINK_API_URL}/create",
    ]

    query_variants = [
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
        {
            "api": VPLINK_API_KEY,
            "link": destination,
        },
    ]

    for endpoint in endpoints:

        for params in query_variants:

            try:

                response = requests.get(
                    endpoint,
                    params=params,
                    timeout=15
                )

                logger.info(
                    "VPLink request %s -> %s",
                    endpoint,
                    response.status_code
                )

                if response.status_code != 200:
                    continue

                try:
                    data = response.json()
                except Exception:
                    data = None

                if isinstance(data, dict):

                    for key in (
                        "shortenedUrl",
                        "shortened_url",
                        "short_url",
                        "short",
                        "url",
                        "link",
                    ):

                        value = data.get(key)

                        if (
                            isinstance(value, str)
                            and value.startswith("http")
                        ):
                            return value

                    result = data.get(
                        "result"
                    )

                    if (
                        isinstance(result, str)
                        and result.startswith("http")
                    ):
                        return result

                    if isinstance(result, dict):

                        for key in (
                            "url",
                            "link",
                            "short_url",
                            "shortenedUrl",
                            "shortened_url",
                        ):

                            value = result.get(key)

                            if (
                                isinstance(value, str)
                                and value.startswith("http")
                            ):
                                return value

                elif isinstance(data, str):

                    value = data.strip()

                    if value.startswith("http"):
                        return value

                raw = response.text.strip()

                if raw.startswith("http"):
                    return raw

            except Exception as e:

                logger.warning(
                    "VPLink request failed: %s",
                    e
                )

    logger.error(
        "Unable to create VPLink."
    )

    return None


# ============================================================
# ACCESS PAGE
# ============================================================

def access_page(target):

    safe_target = html.escape(
        target,
        quote=True
    )

    return HTMLResponse(
        f"""
<!DOCTYPE html>
<html>
<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width,initial-scale=1.0">

<meta http-equiv="refresh"
      content="1;url={safe_target}">

<title>Lozo Gateway</title>

<style>
* {{
    box-sizing:border-box;
}}

body {{
    margin:0;
    min-height:100vh;
    display:flex;
    align-items:center;
    justify-content:center;
    background:linear-gradient(
        135deg,
        #020617,
        #111827,
        #0f172a
    );
    color:white;
    font-family:
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        Roboto,
        Arial,
        sans-serif;
}}

.card {{
    width:calc(100% - 40px);
    max-width:430px;
    padding:34px 25px;
    text-align:center;
    background:rgba(255,255,255,.06);
    border:1px solid rgba(255,255,255,.10);
    border-radius:22px;
    box-shadow:0 20px 60px rgba(0,0,0,.45);
}}

.loader {{
    width:58px;
    height:58px;
    margin:0 auto 22px;
    border:4px solid rgba(255,255,255,.15);
    border-top-color:white;
    border-radius:50%;
    animation:spin .9s linear infinite;
}}

@keyframes spin {{
    to {{ transform:rotate(360deg); }}
}}

h1 {{
    margin:0 0 10px;
    font-size:24px;
}}

p {{
    margin:0;
    color:#cbd5e1;
    line-height:1.6;
    font-size:14px;
}}
</style>

</head>

<body>

<div class="card">

<div class="loader"></div>

<h1>Lozo Gateway</h1>

<p>
Please wait while we redirect you...
</p>

</div>

</body>
</html>
"""
    )


# ============================================================
# VERIFICATION PAGE
# ============================================================

def verification_page(
    verify_id,
    state
):

    safe_verify = html.escape(
        verify_id,
        quote=True
    )

    return HTMLResponse(
        f"""
<!DOCTYPE html>
<html>
<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width,initial-scale=1.0">

<title>Verification - Lozo Gateway</title>

<style>
* {{
    box-sizing:border-box;
}}

body {{
    margin:0;
    min-height:100vh;
    display:flex;
    align-items:center;
    justify-content:center;
    padding:20px;
    background:linear-gradient(
        135deg,
        #020617,
        #111827,
        #0f172a
    );
    color:#fff;
    font-family:
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        Roboto,
        Arial,
        sans-serif;
}}

.card {{
    width:100%;
    max-width:460px;
    padding:32px 25px;
    text-align:center;
    background:rgba(255,255,255,.06);
    border:1px solid rgba(255,255,255,.10);
    border-radius:22px;
    box-shadow:0 20px 60px rgba(0,0,0,.45);
}}

.icon {{
    width:70px;
    height:70px;
    margin:0 auto 20px;
    display:flex;
    align-items:center;
    justify-content:center;
    border-radius:50%;
    background:rgba(59,130,246,.15);
    font-size:32px;
}}

h1 {{
    margin:0 0 12px;
    font-size:25px;
}}

p {{
    margin:0 0 25px;
    color:#cbd5e1;
    line-height:1.6;
    font-size:14px;
}}

.button {{
    display:inline-block;
    padding:13px 24px;
    border-radius:12px;
    background:#2563eb;
    color:white;
    text-decoration:none;
    font-weight:600;
}}
</style>

</head>

<body>

<div class="card">

<div class="icon">✓</div>

<h1>Verification Required</h1>

<p>
Complete the verification below to continue.
</p>

<a
    class="button"
    href="/verify/{safe_verify}"
>
Verify & Continue
</a>

</div>

</body>
</html>
"""
    )


# ============================================================
# ROOT
# ============================================================

@app.get(
    "/",
    response_class=HTMLResponse
)
async def root():

    return HTMLResponse(
        """
<!DOCTYPE html>
<html>
<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width,initial-scale=1.0">

<title>Lozo Gateway</title>

<style>
* {
    box-sizing:border-box;
}

body {
    margin:0;
    min-height:100vh;
    display:flex;
    align-items:center;
    justify-content:center;
    padding:20px;
    background:linear-gradient(
        135deg,
        #020617,
        #111827,
        #0f172a
    );
    color:white;
    font-family:
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        Roboto,
        Arial,
        sans-serif;
}

.card {
    width:100%;
    max-width:460px;
    padding:36px 25px;
    text-align:center;
    background:rgba(255,255,255,.06);
    border:1px solid rgba(255,255,255,.10);
    border-radius:22px;
    box-shadow:0 20px 60px rgba(0,0,0,.45);
}

h1 {
    margin:0 0 12px;
    font-size:28px;
}

p {
    margin:0;
    color:#cbd5e1;
    line-height:1.7;
    font-size:15px;
}
</style>

</head>

<body>

<div class="card">

<h1>Lozo Gateway</h1>

<p>
Secure gateway is active.
</p>

</div>

</body>
</html>
"""
    )


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
async def health():

    return {
        "ok": True,
        "service": "lozo-gateway",
        "database": db_ready()
    }


# ============================================================
# GATEWAY
# ============================================================

@app.get("/api/gateway")
async def gateway(
    request: Request,
    token: str = Query(...)
):

    token = token.strip()

    if not token:

        return error_page(
            "Invalid Link",
            "The requested gateway link is invalid."
        )

    if not db_ready():

        return error_page(
            "Service Unavailable",
            "The gateway database is currently unavailable."
        )

    if not BOT_USERNAME:

        return error_page(
            "Configuration Error",
            "The Telegram bot username is not configured."
        )

    # --------------------------------------------------------
    # TOKEN
    # --------------------------------------------------------

    token_record = get_token_record(
        token
    )

    if not token_record:

        return error_page(
            "Invalid Link",
            "The requested gateway link is invalid or no longer available."
        )

    # --------------------------------------------------------
    # TOKEN EXPIRY
    # --------------------------------------------------------

    token_expires = (
        token_record.get("expires_at")
        or token_record.get("expire_at")
        or token_record.get("expires")
    )

    if (
        token_expires
        and is_expired(token_expires)
    ):

        return error_page(
            "Link Expired",
            EXPIRED_MESSAGE
        )

    # --------------------------------------------------------
    # ONE-TIME ENTRY
    # --------------------------------------------------------

    if token_entry_used(token):

        return error_page(
            "Link Expired",
            EXPIRED_MESSAGE
        )

    # --------------------------------------------------------
    # BROWSER ID
    # --------------------------------------------------------

    browser_id = request.cookies.get(
        BROWSER_COOKIE
    )

    if not browser_id:
        browser_id = random_id(24)

    browser_hash = sha256(
        browser_id
    )

    # --------------------------------------------------------
    # CREATE SESSION
    # --------------------------------------------------------

    access_id = random_id(24)

    expires_at = (
        now_utc()
        + timedelta(
            minutes=SESSION_MINUTES
        )
    )

    saved = save_session(
        access_id,
        token,
        expires_at,
        browser_hash
    )

    if not saved:

        return error_page(
            "Unable to Create Session",
            "Unable to create a secure gateway session. Please try again."
        )

    # --------------------------------------------------------
    # VPLink destination
    # --------------------------------------------------------

    complete_url = (
        f"{GATEWAY_DOMAIN}/api/complete?"
        f"{urlencode({'state': access_id})}"
    )

    vplink_url = create_vplink(
        complete_url
    )

    if not vplink_url:

        delete_session(
            access_id
        )

        return error_page(
            "Gateway Error",
            "Unable to create the gateway link. Please try again."
        )

    # --------------------------------------------------------
    # SAVE VPLink
    # --------------------------------------------------------

    update_session(
        access_id,
        {
            "target": vplink_url
        }
    )

    # --------------------------------------------------------
    # REDIRECT
    # --------------------------------------------------------

    response = RedirectResponse(
        url=f"/access/{access_id}",
        status_code=302
    )

    response.set_cookie(
        key=ACCESS_COOKIE,
        value=access_id,
        max_age=SESSION_MINUTES * 60,
        httponly=True,
        secure=True,
        samesite="lax"
    )

    response.set_cookie(
        key=BROWSER_COOKIE,
        value=browser_id,
        max_age=60 * 60 * 24 * 30,
        httponly=True,
        secure=True,
        samesite="lax"
    )

    response.set_cookie(
        key=VPLINK_COOKIE,
        value=vplink_url,
        max_age=SESSION_MINUTES * 60,
        httponly=True,
        secure=True,
        samesite="lax"
    )

    return response


# ============================================================
# ACCESS
# ============================================================

@app.get("/access/{access_id}")
async def access(
    request: Request,
    access_id: str
):

    session = get_session(
        access_id
    )

    if not session:

        return error_page(
            "Session Expired",
            EXPIRED_MESSAGE
        )

    if session.get("used"):

        return error_page(
            "Session Expired",
            EXPIRED_MESSAGE
        )

    if is_expired(
        session.get("expires_at")
    ):

        return error_page(
            "Session Expired",
            EXPIRED_MESSAGE
        )

    browser_id = request.cookies.get(
        BROWSER_COOKIE
    )

    if not browser_id:

        return error_page(
            "Invalid Session",
            "This session belongs to another browser session."
        )

    browser_hash = sha256(
        browser_id
    )

    if (
        session.get("browser_hash")
        != browser_hash
    ):

        return error_page(
            "Invalid Session",
            "This session belongs to another browser session."
        )

    target = session.get(
        "target"
    )

    if not target:

        return error_page(
            "Gateway Error",
            "The gateway destination is unavailable."
        )

    return access_page(
        target
    )


# ============================================================
# VPLINK COMPLETE
# ============================================================

@app.get("/api/complete")
async def complete(
    request: Request,
    state: str = Query(...)
):

    session = get_session(
        state
    )

    if not session:

        return error_page(
            "Session Expired",
            EXPIRED_MESSAGE
        )

    if session.get("used"):

        return error_page(
            "Session Expired",
            EXPIRED_MESSAGE
        )

    if is_expired(
        session.get("expires_at")
    ):

        return error_page(
            "Session Expired",
            EXPIRED_MESSAGE
        )

    # --------------------------------------------------------
    # BROWSER
    # --------------------------------------------------------

    browser_id = request.cookies.get(
        BROWSER_COOKIE
    )

    if not browser_id:

        return error_page(
            "Invalid Session",
            "This session belongs to another browser session."
        )

    browser_hash = sha256(
        browser_id
    )

    if (
        session.get("browser_hash")
        != browser_hash
    ):

        return error_page(
            "Invalid Session",
            "This session belongs to another browser session."
        )

    # --------------------------------------------------------
    # ALREADY VERIFIED
    # --------------------------------------------------------

    if session.get("verified"):

        return RedirectResponse(
            url=f"/api/deliver?state={state}",
            status_code=302
        )

    # --------------------------------------------------------
    # CREATE CHALLENGE
    # --------------------------------------------------------

    verify_id = random_id(24)

    verify_expires_at = (
        now_utc()
        + timedelta(
            minutes=VERIFY_MINUTES
        )
    )

    updated = update_session(
        state,
        {
            "challenge_hash": sha256(
                verify_id
            ),
            "verify_expires_at": iso(
                verify_expires_at
            )
        }
    )

    if not updated:

        return error_page(
            "Verification Error",
            "Unable to create the verification session."
        )

    return verification_page(
        verify_id,
        state
    )


# ============================================================
# VERIFY
# ============================================================

@app.get("/verify/{verify_id}")
async def verify(
    request: Request,
    verify_id: str
):

    session = get_session_by_verify_id(
        verify_id
    )

    if not session:

        return error_page(
            "Verification Expired",
            EXPIRED_MESSAGE
        )

    state = session.get(
        "state"
    )

    if not state:

        return error_page(
            "Verification Error",
            "Invalid verification session."
        )

    if session.get("used"):

        return error_page(
            "Session Expired",
            EXPIRED_MESSAGE
        )

    if is_expired(
        session.get("expires_at")
    ):

        return error_page(
            "Session Expired",
            EXPIRED_MESSAGE
        )

    # --------------------------------------------------------
    # BROWSER
    # --------------------------------------------------------

    browser_id = request.cookies.get(
        BROWSER_COOKIE
    )

    if not browser_id:

        return error_page(
            "Invalid Session",
            "This session belongs to another browser session."
        )

    browser_hash = sha256(
        browser_id
    )

    if (
        session.get("browser_hash")
        != browser_hash
    ):

        return error_page(
            "Invalid Session",
            "This session belongs to another browser session."
        )

    # --------------------------------------------------------
    # CHALLENGE
    # --------------------------------------------------------

    if (
        session.get("challenge_hash")
        != sha256(verify_id)
    ):

        return error_page(
            "Invalid Verification",
            "The verification request is invalid."
        )

    # --------------------------------------------------------
    # VERIFICATION EXPIRY
    # --------------------------------------------------------

    verify_expires_at = session.get(
        "verify_expires_at"
    )

    if (
        not verify_expires_at
        or is_expired(
            verify_expires_at
        )
    ):

        return error_page(
            "Verification Expired",
            "The verification session has expired. Please start again."
        )

    # --------------------------------------------------------
    # MARK VERIFIED
    # --------------------------------------------------------

    verified_at = now_utc()

    updated = update_session(
        state,
        {
            "verified": True,
            "verified_at": iso(
                verified_at
            )
        }
    )

    if not updated:

        return error_page(
            "Verification Error",
            "Unable to save verification. Please try again."
        )

    # --------------------------------------------------------
    # VERIFICATION COOKIE
    # --------------------------------------------------------

    response = RedirectResponse(
        url=f"/api/deliver?state={state}",
        status_code=302
    )

    response.set_cookie(
        key=VERIFY_COOKIE,
        value=state,
        max_age=VERIFY_MINUTES * 60,
        httponly=True,
        secure=True,
        samesite="lax"
    )

    return response


# ============================================================
# FINAL DELIVERY
# ============================================================

@app.get("/api/deliver")
async def deliver(
    request: Request,
    state: str = Query(...)
):

    session = get_session(
        state
    )

    if not session:

        return error_page(
            "Session Expired",
            EXPIRED_MESSAGE
        )

    # --------------------------------------------------------
    # SESSION
    # --------------------------------------------------------

    if session.get("used"):

        return error_page(
            "Session Expired",
            EXPIRED_MESSAGE
        )

    if is_expired(
        session.get("expires_at")
    ):

        return error_page(
            "Session Expired",
            EXPIRED_MESSAGE
        )

    # --------------------------------------------------------
    # BROWSER
    # --------------------------------------------------------

    browser_id = request.cookies.get(
        BROWSER_COOKIE
    )

    if not browser_id:

        return error_page(
            "Invalid Session",
            "This session belongs to another browser session."
        )

    browser_hash = sha256(
        browser_id
    )

    if (
        session.get("browser_hash")
        != browser_hash
    ):

        return error_page(
            "Invalid Session",
            "This session belongs to another browser session."
        )

    # --------------------------------------------------------
    # VERIFICATION COOKIE
    # --------------------------------------------------------

    verified_cookie = request.cookies.get(
        VERIFY_COOKIE
    )

    if verified_cookie != state:

        return error_page(
            "Verification Required",
            "Please complete the verification before continuing."
        )

    # --------------------------------------------------------
    # VERIFIED
    # --------------------------------------------------------

    if not session.get("verified"):

        return error_page(
            "Verification Required",
            "Please complete the verification before continuing."
        )

    verify_expires_at = session.get(
        "verify_expires_at"
    )

    if (
        not verify_expires_at
        or is_expired(
            verify_expires_at
        )
    ):

        return error_page(
            "Verification Expired",
            "The verification session has expired. Please start again."
        )

    # --------------------------------------------------------
    # ORIGINAL TOKEN
    # --------------------------------------------------------

    original_token = session.get(
        "token"
    )

    if not original_token:

        return error_page(
            "Invalid Session",
            "The original gateway token could not be found."
        )

    token_record = get_token_record(
        original_token
    )

    if not token_record:

        return error_page(
            "Link Expired",
            EXPIRED_MESSAGE
        )

    # --------------------------------------------------------
    # ORIGINAL TOKEN EXPIRY
    # --------------------------------------------------------

    token_expires = (
        token_record.get("expires_at")
        or token_record.get("expire_at")
        or token_record.get("expires")
    )

    if (
        token_expires
        and is_expired(token_expires)
    ):

        return error_page(
            "Link Expired",
            EXPIRED_MESSAGE
        )

    # --------------------------------------------------------
    # TELEGRAM DESTINATION
    # --------------------------------------------------------

    telegram_url = (
        f"https://t.me/{BOT_USERNAME}"
        f"?start=verify_{original_token}"
    )

    # --------------------------------------------------------
    # MARK USED
    # --------------------------------------------------------

    updated = update_session(
        state,
        {
            "used": True
        }
    )

    if not updated:

        return error_page(
            "Delivery Error",
            "Unable to complete the gateway session. Please try again."
        )

    # --------------------------------------------------------
    # REDIRECT TO TELEGRAM
    # --------------------------------------------------------

    response = RedirectResponse(
        url=telegram_url,
        status_code=302
    )

    response.delete_cookie(
        ACCESS_COOKIE
    )

    response.delete_cookie(
        VERIFY_COOKIE
    )

    response.delete_cookie(
        VPLINK_COOKIE
    )

    return response


# ============================================================
# SESSION DEBUG
# ============================================================

@app.get("/api/session")
async def session_info(
    state: str = Query(...)
):

    session = get_session(
        state
    )

    if not session:

        return JSONResponse(
            {
                "ok": False,
                "error": "session_not_found"
            },
            status_code=404
        )

    return {
        "ok": True,
        "state": session.get("state"),
        "token": session.get("token"),
        "expires_at": session.get("expires_at"),
        "used": session.get("used"),
        "entry_used": session.get("entry_used"),
        "verified": session.get("verified"),
        "verified_at": session.get("verified_at"),
        "verify_expires_at": session.get(
            "verify_expires_at"
        ),
    }
