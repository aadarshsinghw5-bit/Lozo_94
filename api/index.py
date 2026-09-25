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


# =========================================================
# CONFIG
# =========================================================

BOT_USERNAME = os.getenv("BOT_USERNAME", "").replace("@", "").strip()

MONGO_URI = os.getenv("MONGO_URI", "").strip()
MONGO_DB = os.getenv("MONGO_DB", "file_store_bot").strip()

VPLINK_API_URL = os.getenv(
    "VPLINK_API_URL",
    "https://vplink.in/api"
).strip().rstrip("/")

VPLINK_API_KEY = os.getenv("VPLINK_API_KEY", "").strip()

GATEWAY_DOMAIN = os.getenv(
    "GATEWAY_DOMAIN",
    "https://lozo-94.vercel.app"
).strip().rstrip("/")

SESSION_MINUTES = int(os.getenv("SESSION_MINUTES", "30"))
VERIFY_MINUTES = int(os.getenv("VERIFY_MINUTES", "10"))


# =========================================================
# APP / LOGGING
# =========================================================

app = FastAPI()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("lozo-gateway")


# =========================================================
# DATABASE
# =========================================================

mongo = None
db = None
DB_ERROR = None


def initialize_database():
    global mongo, db, DB_ERROR

    DB_ERROR = None

    if not MONGO_URI:
        DB_ERROR = "MONGO_URI is not configured"
        logger.error(DB_ERROR)
        return False

    try:
        mongo = MongoClient(
            MONGO_URI,
            serverSelectionTimeoutMS=10000,
            connectTimeoutMS=10000,
            socketTimeoutMS=10000,
        )

        mongo.admin.command("ping")

        db = mongo[MONGO_DB]

        # =================================================
        # TOKENS INDEX
        # token must be UNIQUE
        # =================================================

        token_indexes = {
            idx["name"]: idx
            for idx in db.tokens.list_indexes()
        }

        token_index = token_indexes.get("token_1")

        if token_index:
            if not token_index.get("unique", False):
                logger.info(
                    "Fixing tokens.token_1 -> UNIQUE"
                )

                db.tokens.drop_index("token_1")

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

        # =================================================
        # GATEWAY STATE INDEX
        # state must be UNIQUE
        # =================================================

        gateway_indexes = {
            idx["name"]: idx
            for idx in db.gateway_states.list_indexes()
        }

        state_index = gateway_indexes.get("state_1")

        if state_index:
            if not state_index.get("unique", False):
                logger.info(
                    "Fixing gateway_states.state_1 -> UNIQUE"
                )

                db.gateway_states.drop_index("state_1")

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

        # =================================================
        # GATEWAY TOKEN INDEX
        # token must NOT be UNIQUE
        # =================================================

        gateway_indexes = {
            idx["name"]: idx
            for idx in db.gateway_states.list_indexes()
        }

        gateway_token_index = gateway_indexes.get("token_1")

        if gateway_token_index:
            if gateway_token_index.get("unique", False):
                logger.info(
                    "Removing old UNIQUE gateway_states.token_1"
                )

                db.gateway_states.drop_index("token_1")

                db.gateway_states.create_index(
                    [("token", ASCENDING)],
                    name="token_1",
                    unique=False
                )
        else:
            db.gateway_states.create_index(
                [("token", ASCENDING)],
                name="token_1",
                unique=False
            )

        # =================================================
        # CHALLENGE HASH INDEX
        #
        # IMPORTANT:
        # DO NOT CREATE THIS INDEX.
        #
        # Older deployments may have created
        # challenge_hash_1. Remove it automatically.
        # =================================================

        gateway_indexes = {
            idx["name"]: idx
            for idx in db.gateway_states.list_indexes()
        }

        challenge_index = gateway_indexes.get(
            "challenge_hash_1"
        )

        if challenge_index:
            logger.info(
                "Removing obsolete gateway_states.challenge_hash_1"
            )

            db.gateway_states.drop_index(
                "challenge_hash_1"
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
        DB_ERROR = f"{type(e).__name__}: {str(e)}"

        logger.error(
            "MongoDB initialization failed: %s",
            DB_ERROR
        )

        mongo = None
        db = None

        return False


initialize_database()


def db_ready():
    return db is not None


# =========================================================
# ERROR PAGE
# =========================================================

def error_page(title, message):
    return HTMLResponse(
        f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta
                name="viewport"
                content="width=device-width, initial-scale=1.0"
            >
            <title>{html.escape(title)}</title>

            <style>
                body {{
                    margin: 0;
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    background: #0f0f0f;
                    color: white;
                    font-family: Arial, sans-serif;
                }}

                .box {{
                    width: 90%;
                    max-width: 430px;
                    padding: 30px;
                    box-sizing: border-box;
                    text-align: center;
                    border-radius: 18px;
                    background: #191919;
                    box-shadow: 0 10px 40px rgba(0,0,0,.4);
                }}

                h1 {{
                    margin-bottom: 15px;
                    font-size: 25px;
                }}

                p {{
                    color: #bdbdbd;
                    line-height: 1.6;
                }}

                .brand {{
                    margin-top: 25px;
                    font-size: 13px;
                    color: #777;
                }}
            </style>
        </head>

        <body>
            <div class="box">
                <h1>{html.escape(title)}</h1>
                <p>{html.escape(message)}</p>
                <div class="brand">Lozo Gateway</div>
            </div>
        </body>
        </html>
        """,
        status_code=400
    )


# =========================================================
# DATABASE HELPERS
# =========================================================

def get_token_record(token):
    if not db_ready():
        return None

    return db.tokens.find_one(
        {"token": token},
        {"_id": 0}
    )


def token_entry_used(token):
    if not db_ready():
        return False

    return db.gateway_states.find_one(
        {
            "token": token,
            "entry_used": True
        }
    ) is not None


def get_session(state):
    if not db_ready():
        return None

    return db.gateway_states.find_one(
        {"state": state},
        {"_id": 0}
    )


def get_session_by_verify_id(verify_id):
    if not db_ready():
        return None

    return db.gateway_states.find_one(
        {"verify_id": verify_id},
        {"_id": 0}
    )


def save_session(session):
    if not db_ready():
        return False

    db.gateway_states.insert_one(session)

    return True


def update_session(state, update):
    if not db_ready():
        return False

    result = db.gateway_states.update_one(
        {"state": state},
        {"$set": update}
    )

    return result.modified_count > 0


def delete_session(state):
    if not db_ready():
        return False

    db.gateway_states.delete_one(
        {"state": state}
    )

    return True


# =========================================================
# VPLINK
# =========================================================

def create_vplink(destination):
    if not VPLINK_API_KEY:
        logger.error("VPLINK_API_KEY is missing")
        return None

    endpoints = [
        VPLINK_API_URL,
        f"{VPLINK_API_URL}/shorten",
        f"{VPLINK_API_URL}/create",
    ]

    parameter_sets = [
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
        for params in parameter_sets:
            try:
                logger.info(
                    "Trying VPLink endpoint: %s",
                    endpoint
                )

                response = requests.get(
                    endpoint,
                    params=params,
                    timeout=15
                )

                logger.info(
                    "VPLink response status: %s",
                    response.status_code
                )

                if not response.ok:
                    continue

                content_type = response.headers.get(
                    "content-type",
                    ""
                ).lower()

                # -----------------------------------------
                # JSON
                # -----------------------------------------

                if "application/json" in content_type:

                    try:
                        data = response.json()
                    except Exception:
                        data = None

                    if isinstance(data, dict):

                        for key in [
                            "shortenedUrl",
                            "shortened_url",
                            "short_url",
                            "short",
                            "url",
                            "link",
                        ]:
                            value = data.get(key)

                            if (
                                isinstance(value, str)
                                and value.startswith("http")
                            ):
                                return value

                        nested = data.get("result")

                        if isinstance(nested, dict):

                            for key in [
                                "shortenedUrl",
                                "shortened_url",
                                "short_url",
                                "short",
                                "url",
                                "link",
                            ]:
                                value = nested.get(key)

                                if (
                                    isinstance(value, str)
                                    and value.startswith("http")
                                ):
                                    return value

                        elif (
                            isinstance(nested, str)
                            and nested.startswith("http")
                        ):
                            return nested

                # -----------------------------------------
                # RAW TEXT
                # -----------------------------------------

                text = response.text.strip()

                if text.startswith("http"):
                    return text

            except Exception as e:
                logger.warning(
                    "VPLink request failed: %s",
                    e
                )

    logger.error("Unable to create VPLink")

    return None


# =========================================================
# HOME
# =========================================================

@app.get("/")
def home():
    return HTMLResponse(
        """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">

            <meta
                name="viewport"
                content="width=device-width, initial-scale=1.0"
            >

            <title>Lozo Gateway</title>

            <style>
                body {
                    margin: 0;
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    background: #0f0f0f;
                    color: white;
                    font-family: Arial, sans-serif;
                }

                .box {
                    padding: 35px;
                    text-align: center;
                    border-radius: 18px;
                    background: #191919;
                }

                p {
                    color: #aaa;
                }
            </style>
        </head>

        <body>
            <div class="box">
                <h1>Lozo Gateway</h1>
                <p>Secure gateway is active.</p>
            </div>
        </body>
        </html>
        """
    )


# =========================================================
# HEALTH
# =========================================================

@app.get("/health")
def health():

    result = {
        "ok": True,
        "service": "lozo-gateway",
        "database": db_ready(),
    }

    if not db_ready():

        result["database_write"] = False

        if DB_ERROR:
            result["error_type"] = (
                DB_ERROR.split(":", 1)[0]
            )
            result["error"] = DB_ERROR

        return JSONResponse(
            result,
            status_code=500
        )

    try:

        # IMPORTANT:
        # No challenge_hash field here.
        # This prevents UNIQUE/null conflicts.

        test_state = (
            "__health_test__"
            + secrets.token_hex(8)
        )

        db.gateway_states.insert_one(
            {
                "state": test_state,
                "token": "__health_test__",
                "expires_at": (
                    datetime.now(timezone.utc)
                    + timedelta(minutes=1)
                ),
                "used": False,
                "entry_used": False,
                "verified": False,
            }
        )

        db.gateway_states.delete_one(
            {"state": test_state}
        )

        result["database_write"] = True
        result["message"] = (
            "MongoDB read/write working"
        )

        return JSONResponse(result)

    except Exception as e:

        result["database_write"] = False
        result["error_type"] = type(e).__name__
        result["error"] = str(e)

        return JSONResponse(
            result,
            status_code=500
        )


# =========================================================
# GATEWAY
# =========================================================

@app.get("/api/gateway")
def gateway(
    request: Request,
    token: str = Query("")
):

    token = token.strip()

    if not token:
        return error_page(
            "Invalid Link",
            "No token was provided."
        )

    if not db_ready():
        return error_page(
            "Database Error",
            "Gateway database is unavailable."
        )

    if not BOT_USERNAME:
        return error_page(
            "Configuration Error",
            "Bot username is not configured."
        )

    # -----------------------------------------------------
    # TOKEN
    # -----------------------------------------------------

    token_record = get_token_record(token)

    if not token_record:
        return error_page(
            "Invalid Link",
            "This link is invalid or no longer available."
        )

    # -----------------------------------------------------
    # EXPIRY
    # -----------------------------------------------------

    now = datetime.now(timezone.utc)

    token_expiry = token_record.get(
        "expires_at"
    )

    if token_expiry:

        if token_expiry.tzinfo is None:
            token_expiry = token_expiry.replace(
                tzinfo=timezone.utc
            )

        if token_expiry <= now:
            return error_page(
                "Link Expired",
                "This link has expired."
            )

    # -----------------------------------------------------
    # ALREADY USED
    # -----------------------------------------------------

    if token_entry_used(token):
        return error_page(
            "Link Already Used",
            "This gateway link has already been opened."
        )

    # -----------------------------------------------------
    # BROWSER
    # -----------------------------------------------------

    browser_id = request.cookies.get(
        "lozo_browser_id"
    )

    set_browser_cookie = False

    if not browser_id:
        browser_id = secrets.token_urlsafe(32)
        set_browser_cookie = True

    browser_hash = hashlib.sha256(
        browser_id.encode()
    ).hexdigest()

    # -----------------------------------------------------
    # SESSION
    # -----------------------------------------------------

    state = secrets.token_urlsafe(32)
    access_id = secrets.token_urlsafe(32)

    expires_at = (
        now
        + timedelta(minutes=SESSION_MINUTES)
    )

    session = {
        "state": state,
        "token": token,
        "access_id": access_id,
        "expires_at": expires_at,

        "used": False,
        "entry_used": True,

        "verified": False,
        "verified_at": None,
        "verify_expires_at": None,

        "browser_hash": browser_hash,

        "created_at": now,
        "vplink_url": None,
        "verify_id": None,
    }

    try:

        save_session(session)

    except Exception as e:

        logger.error(
            "Session creation failed: %s",
            e
        )

        return error_page(
            "Unable to Create Session",
            "Unable to create a secure gateway session. Please try again."
        )

    # -----------------------------------------------------
    # VPLINK
    # -----------------------------------------------------

    complete_url = (
        f"{GATEWAY_DOMAIN}/api/complete?"
        + urlencode({"state": state})
    )

    vplink_url = create_vplink(
        complete_url
    )

    if not vplink_url:

        delete_session(state)

        return error_page(
            "Gateway Error",
            "Unable to create gateway link. Please try again."
        )

    update_session(
        state,
        {
            "vplink_url": vplink_url
        }
    )

    # -----------------------------------------------------
    # REDIRECT TO ACCESS
    # -----------------------------------------------------

    response = RedirectResponse(
        url=f"/access/{access_id}",
        status_code=302
    )

    if set_browser_cookie:

        response.set_cookie(
            key="lozo_browser_id",
            value=browser_id,
            max_age=SESSION_MINUTES * 60,
            httponly=True,
            samesite="lax",
            secure=True,
        )

    response.set_cookie(
        key="lozo_access",
        value=access_id,
        max_age=SESSION_MINUTES * 60,
        httponly=True,
        samesite="lax",
        secure=True,
    )

    return response


# =========================================================
# ACCESS
# =========================================================

@app.get("/access/{access_id}")
def access_page(
    request: Request,
    access_id: str
):

    if not db_ready():
        return error_page(
            "Database Error",
            "Gateway database is unavailable."
        )

    session = db.gateway_states.find_one(
        {"access_id": access_id},
        {"_id": 0}
    )

    if not session:
        return error_page(
            "Invalid Session",
            "This gateway session is invalid."
        )

    now = datetime.now(timezone.utc)

    expires_at = session.get(
        "expires_at"
    )

    if expires_at:

        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(
                tzinfo=timezone.utc
            )

        if expires_at <= now:
            return error_page(
                "Session Expired",
                "This gateway session has expired."
            )

    browser_id = request.cookies.get(
        "lozo_browser_id"
    )

    if not browser_id:
        return error_page(
            "Invalid Browser",
            "Please reopen the original gateway link."
        )

    browser_hash = hashlib.sha256(
        browser_id.encode()
    ).hexdigest()

    if browser_hash != session.get(
        "browser_hash"
    ):
        return error_page(
            "Browser Mismatch",
            "This session belongs to another browser."
        )

    vplink_url = session.get(
        "vplink_url"
    )

    if not vplink_url:
        return error_page(
            "Gateway Error",
            "Gateway destination is unavailable."
        )

    escaped_url = html.escape(
        vplink_url,
        quote=True
    )

    return HTMLResponse(
        f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">

            <meta
                name="viewport"
                content="width=device-width, initial-scale=1.0"
            >

            <meta
                http-equiv="refresh"
                content="0;url={escaped_url}"
            >

            <title>Lozo Gateway</title>

            <style>
                body {{
                    margin: 0;
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    background: #0f0f0f;
                    color: white;
                    font-family: Arial, sans-serif;
                }}

                .box {{
                    text-align: center;
                    padding: 30px;
                }}

                p {{
                    color: #aaa;
                }}
            </style>
        </head>

        <body>
            <div class="box">
                <h2>Redirecting...</h2>
                <p>Please wait...</p>
            </div>
        </body>
        </html>
        """
    )


# =========================================================
# COMPLETE
# =========================================================

@app.get("/api/complete")
def complete(
    request: Request,
    state: str = Query("")
):

    state = state.strip()

    if not state:
        return error_page(
            "Invalid Session",
            "No gateway state was provided."
        )

    session = get_session(state)

    if not session:
        return error_page(
            "Invalid Session",
            "This gateway session is invalid."
        )

    now = datetime.now(timezone.utc)

    expires_at = session.get(
        "expires_at"
    )

    if expires_at:

        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(
                tzinfo=timezone.utc
            )

        if expires_at <= now:
            return error_page(
                "Session Expired",
                "This gateway session has expired."
            )

    if session.get("used"):

        return RedirectResponse(
            url=f"/api/deliver?state={state}",
            status_code=302
        )

    # -----------------------------------------------------
    # BROWSER
    # -----------------------------------------------------

    browser_id = request.cookies.get(
        "lozo_browser_id"
    )

    if not browser_id:
        return error_page(
            "Browser Mismatch",
            "Please continue in the same browser."
        )

    browser_hash = hashlib.sha256(
        browser_id.encode()
    ).hexdigest()

    if browser_hash != session.get(
        "browser_hash"
    ):
        return error_page(
            "Browser Mismatch",
            "This session belongs to another browser."
        )

    # -----------------------------------------------------
    # ALREADY VERIFIED
    # -----------------------------------------------------

    if session.get("verified"):

        return RedirectResponse(
            url=f"/api/deliver?state={state}",
            status_code=302
        )

    # -----------------------------------------------------
    # CREATE VERIFY CHALLENGE
    # -----------------------------------------------------

    verify_id = secrets.token_urlsafe(32)

    challenge = secrets.token_urlsafe(32)

    challenge_hash = hashlib.sha256(
        challenge.encode()
    ).hexdigest()

    verify_expires_at = (
        now
        + timedelta(minutes=VERIFY_MINUTES)
    )

    update_session(
        state,
        {
            "verify_id": verify_id,
            "challenge_hash": challenge_hash,
            "verify_expires_at": verify_expires_at,
        }
    )

    verify_url = (
        f"{GATEWAY_DOMAIN}/verify/"
        f"{verify_id}?challenge={challenge}"
    )

    escaped_verify_url = html.escape(
        verify_url,
        quote=True
    )

    return HTMLResponse(
        f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">

            <meta
                name="viewport"
                content="width=device-width, initial-scale=1.0"
            >

            <title>Verification</title>

            <style>
                body {{
                    margin: 0;
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    background: #0f0f0f;
                    color: white;
                    font-family: Arial, sans-serif;
                }}

                .box {{
                    width: 90%;
                    max-width: 430px;
                    box-sizing: border-box;
                    padding: 30px;
                    text-align: center;
                    border-radius: 18px;
                    background: #191919;
                }}

                h1 {{
                    margin-bottom: 12px;
                }}

                p {{
                    color: #aaa;
                    line-height: 1.6;
                }}

                .btn {{
                    display: inline-block;
                    margin-top: 20px;
                    padding: 14px 25px;
                    border-radius: 10px;
                    background: #ffffff;
                    color: #000000;
                    text-decoration: none;
                    font-weight: bold;
                }}

                .brand {{
                    margin-top: 25px;
                    color: #777;
                    font-size: 13px;
                }}
            </style>
        </head>

        <body>
            <div class="box">
                <h1>Verification Required</h1>

                <p>
                    Complete the verification to continue.
                </p>

                <a
                    class="btn"
                    href="{escaped_verify_url}"
                >
                    Verify
                </a>

                <div class="brand">
                    Lozo Gateway
                </div>
            </div>
        </body>
        </html>
        """
    )


# =========================================================
# VERIFY
# =========================================================

@app.get("/verify/{verify_id}")
def verify(
    request: Request,
    verify_id: str,
    challenge: str = Query("")
):

    session = get_session_by_verify_id(
        verify_id
    )

    if not session:
        return error_page(
            "Invalid Verification",
            "This verification session is invalid."
        )

    now = datetime.now(timezone.utc)

    # -----------------------------------------------------
    # BROWSER
    # -----------------------------------------------------

    browser_id = request.cookies.get(
        "lozo_browser_id"
    )

    if not browser_id:
        return error_page(
            "Browser Mismatch",
            "Please continue in the same browser."
        )

    browser_hash = hashlib.sha256(
        browser_id.encode()
    ).hexdigest()

    if browser_hash != session.get(
        "browser_hash"
    ):
        return error_page(
            "Browser Mismatch",
            "This session belongs to another browser."
        )

    # -----------------------------------------------------
    # VERIFY EXPIRY
    # -----------------------------------------------------

    verify_expires_at = session.get(
        "verify_expires_at"
    )

    if not verify_expires_at:
        return error_page(
            "Verification Expired",
            "This verification session is no longer valid."
        )

    if verify_expires_at.tzinfo is None:
        verify_expires_at = verify_expires_at.replace(
            tzinfo=timezone.utc
        )

    if verify_expires_at <= now:
        return error_page(
            "Verification Expired",
            "Please start the gateway again."
        )

    # -----------------------------------------------------
    # CHALLENGE
    # -----------------------------------------------------

    expected_hash = session.get(
        "challenge_hash"
    )

    actual_hash = hashlib.sha256(
        challenge.encode()
    ).hexdigest()

    if not challenge or actual_hash != expected_hash:
        return error_page(
            "Invalid Verification",
            "The verification challenge is invalid."
        )

    # -----------------------------------------------------
    # MARK VERIFIED
    # -----------------------------------------------------

    update_session(
        session["state"],
        {
            "verified": True,
            "verified_at": now,
        }
    )

    response = RedirectResponse(
        url=(
            f"/api/deliver?"
            f"state={session['state']}"
        ),
        status_code=302
    )

    response.set_cookie(
        key="lozo_verified",
        value="1",
        max_age=VERIFY_MINUTES * 60,
        httponly=True,
        samesite="lax",
        secure=True,
    )

    return response


# =========================================================
# DELIVERY
# =========================================================

@app.get("/api/deliver")
def deliver(
    request: Request,
    state: str = Query("")
):

    state = state.strip()

    if not state:
        return error_page(
            "Invalid Session",
            "No session was provided."
        )

    session = get_session(state)

    if not session:
        return error_page(
            "Invalid Session",
            "This gateway session is invalid."
        )

    now = datetime.now(timezone.utc)

    # -----------------------------------------------------
    # BROWSER
    # -----------------------------------------------------

    browser_id = request.cookies.get(
        "lozo_browser_id"
    )

    if not browser_id:
        return error_page(
            "Browser Mismatch",
            "Please continue in the same browser."
        )

    browser_hash = hashlib.sha256(
        browser_id.encode()
    ).hexdigest()

    if browser_hash != session.get(
        "browser_hash"
    ):
        return error_page(
            "Browser Mismatch",
            "This session belongs to another browser."
        )

    # -----------------------------------------------------
    # SESSION EXPIRY
    # -----------------------------------------------------

    expires_at = session.get(
        "expires_at"
    )

    if expires_at:

        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(
                tzinfo=timezone.utc
            )

        if expires_at <= now:
            return error_page(
                "Session Expired",
                "This gateway session has expired."
            )

    # -----------------------------------------------------
    # VERIFICATION
    # -----------------------------------------------------

    verified_cookie = request.cookies.get(
        "lozo_verified"
    )

    if not session.get("verified"):

        if verified_cookie != "1":
            return error_page(
                "Verification Required",
                "Please complete verification first."
            )

    # -----------------------------------------------------
    # VERIFICATION EXPIRY
    # -----------------------------------------------------

    verify_expires_at = session.get(
        "verify_expires_at"
    )

    if verify_expires_at:

        if verify_expires_at.tzinfo is None:
            verify_expires_at = verify_expires_at.replace(
                tzinfo=timezone.utc
            )

        if verify_expires_at <= now:
            return error_page(
                "Verification Expired",
                "Please start the gateway again."
            )

    # -----------------------------------------------------
    # ALREADY DELIVERED
    # -----------------------------------------------------

    if session.get("used"):
        return error_page(
            "Link Already Used",
            "This gateway session has already been used."
        )

    # -----------------------------------------------------
    # ORIGINAL TOKEN
    # -----------------------------------------------------

    original_token = session.get(
        "token"
    )

    if not original_token:
        return error_page(
            "Gateway Error",
            "Original token is missing."
        )

    token_record = get_token_record(
        original_token
    )

    if not token_record:
        return error_page(
            "Invalid Link",
            "The original token no longer exists."
        )

    token_expiry = token_record.get(
        "expires_at"
    )

    if token_expiry:

        if token_expiry.tzinfo is None:
            token_expiry = token_expiry.replace(
                tzinfo=timezone.utc
            )

        if token_expiry <= now:
            return error_page(
                "Link Expired",
                "This file link has expired."
            )

    # -----------------------------------------------------
    # MARK SESSION USED
    # -----------------------------------------------------

    result = db.gateway_states.update_one(
        {
            "state": state,
            "used": False,
        },
        {
            "$set": {
                "used": True,
                "delivered_at": now,
            }
        }
    )

    if result.modified_count != 1:
        return error_page(
            "Link Already Used",
            "This gateway session has already been used."
        )

    # -----------------------------------------------------
    # TELEGRAM
    # -----------------------------------------------------

    telegram_url = (
        f"https://t.me/{BOT_USERNAME}"
        f"?start=verify_{original_token}"
    )

    response = RedirectResponse(
        url=telegram_url,
        status_code=302
    )

    response.delete_cookie(
        "lozo_browser_id"
    )

    response.delete_cookie(
        "lozo_access"
    )

    response.delete_cookie(
        "lozo_verified"
    )

    response.delete_cookie(
        "lozo_vplink"
    )

    return response


# =========================================================
# DEBUG SESSION
# =========================================================

@app.get("/api/session")
def debug_session(
    state: str = Query("")
):

    if not state:
        return JSONResponse(
            {
                "ok": False,
                "error": "state is required"
            },
            status_code=400
        )

    session = get_session(state)

    if not session:
        return JSONResponse(
            {
                "ok": False,
                "error": "session not found"
            },
            status_code=404
        )

    safe = dict(session)

    safe.pop(
        "browser_hash",
        None
    )

    safe.pop(
        "challenge_hash",
        None
    )

    safe.pop(
        "vplink_url",
        None
    )

    return JSONResponse(
        {
            "ok": True,
            "session": safe
        }
    )
