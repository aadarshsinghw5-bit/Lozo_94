
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
from pymongo import MongoClient, ASCENDING, ReturnDocument
from pymongo.errors import DuplicateKeyError


# =========================================================
# CONFIG
# =========================================================

BOT_USERNAME = os.getenv("BOT_USERNAME", "").replace("@", "").strip()
BOT2_USERNAME = os.getenv("BOT2_USERNAME", "").replace("@", "").strip()

MONGO_URI = os.getenv("MONGO_URI", "").strip()
MONGO_DB = os.getenv("MONGO_DB", "file_store_bot").strip()

SHORTENER1_API_URL = os.getenv("SHORTENER1_API_URL", "").strip().rstrip("/")
SHORTENER1_API_KEY = os.getenv("SHORTENER1_API_KEY", "").strip()

SHORTENER2_API_URL = os.getenv("SHORTENER2_API_URL", "").strip().rstrip("/")
SHORTENER2_API_KEY = os.getenv("SHORTENER2_API_KEY", "").strip()

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

        # Token indexes: keep compatible with existing collections.
        for collection_name in (
            "bot_bot1_tokens",
            "bot_bot2_tokens",
            "tokens",
        ):
            collection = db[collection_name]

            try:
                indexes = {
                    idx["name"]: idx
                    for idx in collection.list_indexes()
                }

                token_index = indexes.get("token_1")

                if token_index and not token_index.get("unique", False):
                    collection.drop_index("token_1")
                    collection.create_index(
                        [("token", ASCENDING)],
                        name="token_1",
                        unique=True,
                    )
                elif not token_index:
                    collection.create_index(
                        [("token", ASCENDING)],
                        name="token_1",
                        unique=True,
                    )

            except Exception as exc:
                logger.warning(
                    "Token index check failed for %s: %s",
                    collection_name,
                    exc,
                )

        
        # Gateway sessions.
        states = db.gateway_states

        # Keep existing indexes compatible; don't recreate them blindly.
        existing_indexes = {
            idx["name"]: idx
            for idx in states.list_indexes()
        }

        # Standard indexes.
        if "state_1" not in existing_indexes:
            states.create_index(
                [("state", ASCENDING)],
                name="state_1",
                unique=True,
            )

        if "token_1" not in existing_indexes:
            states.create_index(
                [("token", ASCENDING)],
                name="token_1",
                unique=False,
            )

        if "access_id_1" not in existing_indexes:
            states.create_index(
                [("access_id", ASCENDING)],
                name="access_id_1",
                unique=True,
            )

        # verify_id: old documents may have missing/null values.
        # A partial unique index ignores documents without a string verify_id.
        verify_index = existing_indexes.get("verify_id_1")

        if verify_index:
            is_compatible = (
                verify_index.get("unique", False)
                and verify_index.get("partialFilterExpression")
                == {"verify_id": {"$type": "string"}}
            )

            if not is_compatible:
                states.drop_index("verify_id_1")
                states.create_index(
                    [("verify_id", ASCENDING)],
                    name="verify_id_1",
                    unique=True,
                    partialFilterExpression={
                        "verify_id": {"$type": "string"}
                    },
                )
        else:
            states.create_index(
                [("verify_id", ASCENDING)],
                name="verify_id_1",
                unique=True,
                partialFilterExpression={
                    "verify_id": {"$type": "string"}
                },
            )


        # Gateway entry links.
        db.gateway_entries.create_index(
            [("entry_id", ASCENDING)],
            name="entry_id_1",
            unique=True,
        )
        db.gateway_entries.create_index(
            [("token", ASCENDING)],
            name="gateway_entry_token_1",
            unique=False,
        )

        # Permanent shortener: one record per bot/file token.
        db.file_shorteners.create_index(
            [("file_key", ASCENDING)],
            name="file_key_1",
            unique=True,
        )

        # Preserve the existing provider rotation setting.
        db.gateway_settings.update_one(
            {"_id": "shortener_rotation"},
            {"$setOnInsert": {"next": 1}},
            upsert=True,
        )

        logger.info("MongoDB connected: %s", MONGO_DB)
        return True

    except Exception as exc:
        DB_ERROR = f"{type(exc).__name__}: {exc}"
        logger.error("MongoDB initialization failed: %s", DB_ERROR)
        mongo = None
        db = None
        return False


initialize_database()


def db_ready():
    return db is not None


# =========================================================
# TOKEN HELPERS
# =========================================================

def get_token_record(token):
    if not db_ready():
        return None

    for collection_name, bot_id in (
        ("bot_bot1_tokens", "bot1"),
        ("bot_bot2_tokens", "bot2"),
        ("tokens", None),
    ):
        try:
            record = db[collection_name].find_one(
                {"token": token},
                {"_id": 0},
            )

            if record:
                record["_gateway_bot_id"] = (
                    record.get("bot_id") or bot_id or "bot1"
                )
                return record

        except Exception as exc:
            logger.warning(
                "Token lookup failed for %s: %s",
                collection_name,
                exc,
            )

    return None


def get_bot_username(bot_id):
    if str(bot_id or "bot1").lower().strip() == "bot2":
        return BOT2_USERNAME
    return BOT_USERNAME


def token_is_expired(record, now=None):
    now = now or datetime.now(timezone.utc)
    expiry = record.get("expires_at")

    if not expiry:
        return False

    if isinstance(expiry, str):
        try:
            expiry = datetime.fromisoformat(
                expiry.replace("Z", "+00:00")
            )
        except ValueError:
            return True

    if not isinstance(expiry, datetime):
        return True

    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)

    return expiry <= now


# =========================================================
# ERROR PAGE
# =========================================================

def error_page(title, message):
    return HTMLResponse(
        f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{html.escape(title)}</title>
<style>
body {{
    margin:0; min-height:100vh; display:flex;
    align-items:center; justify-content:center;
    background:#0f0f0f; color:white;
    font-family:Arial,sans-serif;
}}
.box {{
    width:90%; max-width:430px; padding:30px;
    box-sizing:border-box; text-align:center;
    border-radius:18px; background:#191919;
}}
h1 {{ margin-bottom:15px; font-size:25px; }}
p {{ color:#bdbdbd; line-height:1.6; }}
.brand {{ margin-top:25px; font-size:13px; color:#777; }}
</style>
</head>
<body>
<div class="box">
<h1>{html.escape(title)}</h1>
<p>{html.escape(message)}</p>
<div class="brand">Lozo Gateway</div>
</div>
</body>
</html>""",
        status_code=400,
    )


def already_used_page():
    return error_page(
        "This Link Is Already Used",
        "This session has already been used. Please start again from the bot.",
    )


# =========================================================
# SESSION HELPERS
# =========================================================

def get_session(state):
    if not db_ready():
        return None
    return db.gateway_states.find_one({"state": state}, {"_id": 0})


def get_session_by_verify_id(verify_id):
    if not db_ready():
        return None
    return db.gateway_states.find_one(
        {"verify_id": verify_id},
        {"_id": 0},
    )


def update_session(state, update):
    result = db.gateway_states.update_one(
        {"state": state},
        {"$set": update},
    )
    return result.modified_count > 0


def delete_session(state):
    db.gateway_states.delete_one({"state": state})


def session_expired(session, now=None):
    now = now or datetime.now(timezone.utc)
    expiry = session.get("expires_at")

    if not expiry:
        return True

    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)

    return expiry <= now


def browser_matches(request, session):
    browser_id = request.cookies.get("lozo_browser_id")
    if not browser_id:
        return False

    browser_hash = hashlib.sha256(
        browser_id.encode()
    ).hexdigest()

    return secrets.compare_digest(
        browser_hash,
        str(session.get("browser_hash", "")),
    )


# =========================================================
# SHORTENER RESPONSE HELPERS
# =========================================================

SHORT_URL_KEYS = (
    "shortenedUrl",
    "shortened_url",
    "short_url",
    "shortUrl",
    "short",
    "shortLink",
    "short_link",
    "shortened",
    "link",
    "url",
)


def extract_short_url(data):
    if isinstance(data, str):
        value = data.strip()
        if value.startswith(("http://", "https://")):
            return value
        return None

    if isinstance(data, dict):
        for key in SHORT_URL_KEYS:
            value = data.get(key)
            if isinstance(value, str):
                value = value.strip()
                if value.startswith(("http://", "https://")):
                    return value

        for key in ("result", "data", "response", "resultData"):
            result = extract_short_url(data.get(key))
            if result:
                return result

    if isinstance(data, list):
        for item in data:
            result = extract_short_url(item)
            if result:
                return result

    return None


def parse_shortener_response(response):
    if not response.ok:
        logger.warning(
            "Shortener HTTP %s: %s",
            response.status_code,
            response.text[:300],
        )
        return None

    try:
        result = extract_short_url(response.json())
        if result:
            return result
    except Exception:
        pass

    text = response.text.strip()
    if text.startswith(("http://", "https://")):
        return text

    return None


# =========================================================
# GENERIC SHORTENER API
# =========================================================

def unique_endpoints(base):
    base = (base or "").rstrip("/")
    if not base:
        return []

    values = [
        base,
        f"{base}/shorten",
        f"{base}/create",
        f"{base}/api/shorten",
        f"{base}/api/create",
        f"{base}/api/v1/shorten",
        f"{base}/api/v1/shorten/",
    ]

    return list(dict.fromkeys(values))


def create_generic_shortener(destination, api_url, api_key):
    if not api_url or not api_key:
        return None

    endpoints = unique_endpoints(api_url)

    get_parameters = [
        {"api": api_key, "url": destination},
        {"api_key": api_key, "url": destination},
        {"key": api_key, "url": destination},
        {"token": api_key, "url": destination},
        {"apikey": api_key, "url": destination},
        {"api": api_key, "link": destination},
        {"api_key": api_key, "link": destination},
        {"key": api_key, "link": destination},
    ]

    for endpoint in endpoints:
        for params in get_parameters:
            try:
                response = requests.get(
                    endpoint,
                    params=params,
                    timeout=20,
                )
                result = parse_shortener_response(response)
                if result:
                    return result
            except Exception as exc:
                logger.warning("Shortener GET failed: %s", exc)

    post_payloads = [
        {"url": destination, "api": api_key},
        {"url": destination, "api_key": api_key},
        {"url": destination, "key": api_key},
        {"link": destination, "api": api_key},
        {"link": destination, "api_key": api_key},
        {"originalURL": destination, "api": api_key},
        {"long_url": destination, "api": api_key},
        {"destination": destination, "api": api_key},
    ]

    for endpoint in endpoints:
        for payload in post_payloads:
            try:
                response = requests.post(
                    endpoint,
                    json=payload,
                    timeout=20,
                )
                result = parse_shortener_response(response)
                if result:
                    return result
            except Exception as exc:
                logger.warning("Shortener POST JSON failed: %s", exc)

    for endpoint in endpoints:
        for payload in post_payloads:
            try:
                response = requests.post(
                    endpoint,
                    data=payload,
                    timeout=20,
                )
                result = parse_shortener_response(response)
                if result:
                    return result
            except Exception as exc:
                logger.warning("Shortener POST form failed: %s", exc)

    return None


# =========================================================
# SHORTENER ROTATION
# =========================================================

def get_next_shortener():
    if not db_ready():
        return 1

    try:
        document = db.gateway_settings.find_one_and_update(
            {"_id": "shortener_rotation"},
            {"$setOnInsert": {"next": 1}},
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )

        current = int(document.get("next", 1))
        next_value = 2 if current == 1 else 1

        db.gateway_settings.update_one(
            {"_id": "shortener_rotation"},
            {"$set": {"next": next_value}},
        )

        return current

    except Exception as exc:
        logger.warning("Shortener rotation failed: %s", exc)
        return 1


def create_shortener_link(destination):
    available = []

    if SHORTENER1_API_URL and SHORTENER1_API_KEY:
        available.append(1)

    if SHORTENER2_API_URL and SHORTENER2_API_KEY:
        available.append(2)

    if not available:
        logger.error("No shortener configured")
        return None, None

    selected = get_next_shortener()

    if selected not in available:
        selected = available[0]

    def config(number):
        if number == 1:
            return SHORTENER1_API_URL, SHORTENER1_API_KEY
        return SHORTENER2_API_URL, SHORTENER2_API_KEY

    api_url, api_key = config(selected)

    logger.info("Selected shortener provider: %s", selected)
    result = create_generic_shortener(destination, api_url, api_key)

    if result:
        return result, selected

    other = 2 if selected == 1 else 1
    api_url, api_key = config(other)

    if api_url and api_key:
        logger.warning("Trying fallback shortener provider %s", other)
        result = create_generic_shortener(destination, api_url, api_key)
        if result:
            return result, other

    return None, None


# =========================================================
# PER-FILE PERMANENT SHORTENER
# =========================================================

def get_or_create_file_shortener(token, bot_id, bot_username):
    """
    Each bot/file token gets one permanent shortener URL.
    The destination is the Telegram deep link, NOT a temporary
    gateway verification URL.
    """

    if not db_ready():
        return None, None

    token = str(token or "").strip()
    bot_id = str(bot_id or "bot1").lower().strip()
    bot_username = str(bot_username or "").replace("@", "").strip()

    if not token or not bot_username:
        return None, None

    file_key = f"{bot_id}:{token}"

    existing = db.file_shorteners.find_one(
        {"file_key": file_key},
        {"_id": 0},
    )

    if existing and existing.get("shortener_url"):
        return (
            existing["shortener_url"],
            existing.get("shortener_number"),
        )

    destination = (
        f"https://t.me/{bot_username}"
        f"?start=verify_{token}"
    )

    shortener_url, shortener_number = create_shortener_link(
        destination
    )

    if not shortener_url:
        return None, None

    document = {
        "file_key": file_key,
        "token": token,
        "bot_id": bot_id,
        "bot_username": bot_username,
        "destination": destination,
        "shortener_url": shortener_url,
        "shortener_number": shortener_number,
        "created_at": datetime.now(timezone.utc),
    }

    try:
        db.file_shorteners.insert_one(document)
        logger.info(
            "Permanent shortener created: %s provider=%s",
            file_key,
            shortener_number,
        )
        return shortener_url, shortener_number

    except DuplicateKeyError:
        # A concurrent request may have created the same file link.
        existing = db.file_shorteners.find_one(
            {"file_key": file_key},
            {"_id": 0},
        )

        if existing and existing.get("shortener_url"):
            return (
                existing["shortener_url"],
                existing.get("shortener_number"),
            )

        return None, None

    except Exception as exc:
        logger.error("Saving permanent shortener failed: %s", exc)

        existing = db.file_shorteners.find_one(
            {"file_key": file_key},
            {"_id": 0},
        )

        if existing and existing.get("shortener_url"):
            return (
                existing["shortener_url"],
                existing.get("shortener_number"),
            )

        return None, None


# =========================================================
# HOME
# =========================================================

@app.get("/")
def home():
    return HTMLResponse(
        """<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Lozo Gateway</title>
<style>
body { margin:0; min-height:100vh; display:flex; align-items:center;
justify-content:center; background:#0f0f0f; color:white; font-family:Arial,sans-serif; }
.box { padding:35px; text-align:center; border-radius:18px; background:#191919; }
p { color:#aaa; }
</style>
</head>
<body><div class="box"><h1>Lozo Gateway</h1><p>Secure gateway is active.</p></div></body>
</html>"""
    )


# =========================================================
# HEALTH
# =========================================================

@app.get("/health")
def health():
    return JSONResponse({
        "ok": True,
        "service": "lozo-gateway",
        "database": db_ready(),
        "shortener1": bool(SHORTENER1_API_URL and SHORTENER1_API_KEY),
        "shortener2": bool(SHORTENER2_API_URL and SHORTENER2_API_KEY),
        "rotation": True,
        "per_file_shortener": True,
        "token_namespaces": [
            "bot_bot1_tokens",
            "bot_bot2_tokens",
            "tokens",
        ],
        "gateway_entries": db_ready(),
    })


# =========================================================
# GATEWAY ENTRY
# =========================================================

@app.get("/api/gateway")
def gateway(request: Request, entry: str = Query("")):
    entry = entry.strip()

    if not entry:
        return error_page("Invalid Link", "No gateway entry was provided.")

    if not db_ready():
        return error_page("Database Error", "Gateway database is unavailable.")

    # Entry links can be opened again. Each visit creates a fresh
    # verification session; the permanent shortener is reused later.
    gateway_entry = db.gateway_entries.find_one(
        {"entry_id": entry},
        {"_id": 0},
    )

    if not gateway_entry:
        return error_page(
            "Invalid Link",
            "This gateway link is invalid or no longer available.",
        )

    original_token = str(gateway_entry.get("token") or "").strip()

    if not original_token:
        return error_page("Invalid Link", "Original token is missing.")

    token_record = get_token_record(original_token)

    if not token_record:
        return error_page(
            "Invalid Link",
            "This link is invalid or no longer available.",
        )

    now = datetime.now(timezone.utc)

    if token_is_expired(token_record, now):
        return error_page("Link Expired", "This file link has expired.")

    bot_id = (
        token_record.get("_gateway_bot_id")
        or token_record.get("bot_id")
        or "bot1"
    )

    bot_username = (
        gateway_entry.get("bot_username")
        or get_bot_username(bot_id)
    )

    if not bot_username:
        return error_page(
            "Configuration Error",
            f"Bot username for {bot_id} is not configured.",
        )

    browser_id = request.cookies.get("lozo_browser_id")
    set_browser_cookie = not bool(browser_id)

    if not browser_id:
        browser_id = secrets.token_urlsafe(32)

    browser_hash = hashlib.sha256(browser_id.encode()).hexdigest()
    state = secrets.token_urlsafe(32)
    access_id = secrets.token_urlsafe(24)

    session = {
        "state": state,
        "access_id": access_id,
        "entry_id": entry,
        "token": original_token,
        "bot_id": bot_id,
        "bot_username": bot_username,
        "browser_hash": browser_hash,
        "created_at": now,
        "expires_at": now + timedelta(minutes=SESSION_MINUTES),
        "opened": False,
        "used": False,
        "verified": False,
    }

    try:
        db.gateway_states.insert_one(session)
    except Exception as exc:
        logger.error("Unable to save gateway session: %s", exc)
        return error_page("Gateway Error", "Unable to create gateway session.")

    response = RedirectResponse(
        url=f"/access/{access_id}",
        status_code=302,
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
# ACCESS -> INITIAL VERIFICATION
# =========================================================

@app.get("/access/{access_id}")
def access_page(request: Request, access_id: str):
    if not db_ready():
        return error_page("Database Error", "Gateway database is unavailable.")

    session = db.gateway_states.find_one(
        {"access_id": access_id},
        {"_id": 0},
    )

    if not session:
        return error_page("Invalid Session", "This gateway session is invalid.")

    now = datetime.now(timezone.utc)

    if session_expired(session, now):
        return error_page("Session Expired", "This gateway session has expired.")

    if session.get("opened"):
        return already_used_page()

    if not browser_matches(request, session):
        return error_page(
            "Browser Mismatch",
            "Please reopen the original gateway link in the same browser.",
        )

    result = db.gateway_states.update_one(
        {"access_id": access_id, "opened": False},
        {"$set": {"opened": True, "opened_at": now}},
    )

    if result.modified_count != 1:
        return already_used_page()

    # Verification is now the first gateway page.
    return RedirectResponse(
        url=f"/api/complete?state={session['state']}",
        status_code=302,
    )


# =========================================================
# INITIAL VERIFICATION PAGE
# =========================================================

@app.get("/api/complete")
def complete(request: Request, state: str = Query("")):
    state = state.strip()

    if not state:
        return error_page("Invalid Session", "No gateway state was provided.")

    session = get_session(state)

    if not session:
        return error_page("Invalid Session", "This gateway session is invalid.")

    if session.get("opened") is not True:
        return error_page(
            "Invalid Session",
            "This gateway session has not been opened correctly.",
        )

    if session.get("used"):
        return already_used_page()

    now = datetime.now(timezone.utc)

    if session_expired(session, now):
        return error_page("Session Expired", "This gateway session has expired.")

    if not browser_matches(request, session):
        return error_page(
            "Browser Mismatch",
            "Please continue in the same browser.",
        )

    verify_id = secrets.token_urlsafe(32)
    challenge = secrets.token_urlsafe(32)
    challenge_hash = hashlib.sha256(challenge.encode()).hexdigest()

    verify_expires_at = now + timedelta(minutes=VERIFY_MINUTES)

    update_session(
        state,
        {
            "verify_id": verify_id,
            "challenge_hash": challenge_hash,
            "verify_expires_at": verify_expires_at,
        },
    )

    verify_url = (
        f"{GATEWAY_DOMAIN}/verify/{verify_id}"
        f"?challenge={challenge}"
    )
    escaped_verify_url = html.escape(verify_url, quote=True)

    return HTMLResponse(
        f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Verification</title>
<style>
body {{ margin:0; min-height:100vh; display:flex; align-items:center;
justify-content:center; background:#0f0f0f; color:white; font-family:Arial,sans-serif; }}
.box {{ width:90%; max-width:430px; box-sizing:border-box; padding:30px;
text-align:center; border-radius:18px; background:#191919; }}
p {{ color:#aaa; line-height:1.6; }}
.btn {{ display:inline-block; margin-top:20px; padding:14px 25px;
border-radius:10px; background:#fff; color:#000; text-decoration:none; font-weight:bold; }}
.brand {{ margin-top:25px; color:#777; font-size:13px; }}
</style>
</head>
<body>
<div class="box">
<h1>Verification Required</h1>
<p>Complete the verification to continue.</p>
<a class="btn" href="{escaped_verify_url}">Verify</a>
<div class="brand">Lozo Gateway</div>
</div>
</body>
</html>"""
    )


# =========================================================
# VERIFY -> PERMANENT SHORTENER
# =========================================================

@app.get("/verify/{verify_id}")
def verify(
    request: Request,
    verify_id: str,
    challenge: str = Query(""),
):
    session = get_session_by_verify_id(verify_id)

    if not session:
        return error_page(
            "Invalid Verification",
            "This verification session is invalid.",
        )

    if session.get("used"):
        return already_used_page()

    now = datetime.now(timezone.utc)

    if session_expired(session, now):
        return error_page("Session Expired", "Please start the gateway again.")

    if not browser_matches(request, session):
        return error_page(
            "Browser Mismatch",
            "Please continue in the same browser.",
        )

    verify_expires_at = session.get("verify_expires_at")

    if not verify_expires_at:
        return error_page(
            "Verification Expired",
            "This verification session is no longer valid.",
        )

    if verify_expires_at.tzinfo is None:
        verify_expires_at = verify_expires_at.replace(tzinfo=timezone.utc)

    if verify_expires_at <= now:
        return error_page(
            "Verification Expired",
            "Please start the gateway again.",
        )

    expected_hash = session.get("challenge_hash", "")
    actual_hash = hashlib.sha256(challenge.encode()).hexdigest()

    if not challenge or not secrets.compare_digest(
        actual_hash,
        expected_hash,
    ):
        return error_page(
            "Invalid Verification",
            "The verification challenge is invalid.",
        )

    # Record that initial gateway verification succeeded.
    result = db.gateway_states.update_one(
        {
            "state": session["state"],
            "verified": False,
            "used": False,
        },
        {
            "$set": {
                "verified": True,
                "verified_at": now,
            }
        },
    )

    if result.modified_count != 1:
        refreshed = get_session(session["state"])
        if not refreshed or not refreshed.get("verified"):
            return already_used_page()

    # This creates or reuses the file's permanent shortener.
    original_token = session.get("token")

    if not original_token:
        return error_page("Gateway Error", "Original token is missing.")

    token_record = get_token_record(original_token)

    if not token_record:
        return error_page(
            "Invalid Link",
            "The original token no longer exists.",
        )

    if token_is_expired(token_record, now):
        return error_page("Link Expired", "This file link has expired.")

    bot_id = (
        session.get("bot_id")
        or token_record.get("_gateway_bot_id")
        or token_record.get("bot_id")
        or "bot1"
    )

    bot_username = (
        session.get("bot_username")
        or get_bot_username(bot_id)
    )

    if not bot_username:
        return error_page(
            "Configuration Error",
            f"Bot username for {bot_id} is not configured.",
        )

    shortener_url, shortener_number = get_or_create_file_shortener(
        original_token,
        bot_id,
        bot_username,
    )

    if not shortener_url:
        return error_page(
            "Gateway Error",
            "Unable to create the permanent shortener link. Please try again.",
        )

    # Consume this browser verification session. The saved shortener
    # itself remains reusable for future gateway visits.
    result = db.gateway_states.update_one(
        {
            "state": session["state"],
            "used": False,
        },
        {
            "$set": {
                "used": True,
                "delivered_at": now,
                "shortener_url": shortener_url,
                "shortener_number": shortener_number,
            }
        },
    )

    if result.modified_count != 1:
        return already_used_page()

    response = RedirectResponse(
        url=shortener_url,
        status_code=302,
    )

    response.delete_cookie("lozo_browser_id")
    response.delete_cookie("lozo_access")
    response.delete_cookie("lozo_verified")

    logger.info(
        "Verified; redirecting to permanent shortener: bot=%s provider=%s",
        bot_id,
        shortener_number,
    )

    return response


# =========================================================
# LEGACY DELIVERY ENDPOINT
# =========================================================

@app.get("/api/deliver")
def deliver(state: str = Query("")):
    """
    Compatibility endpoint for old sessions.
    New sessions redirect directly to the permanent shortener
    from /verify/{verify_id}; no final gateway verification page.
    """
    if not state:
        return error_page("Invalid Session", "No session was provided.")

    session = get_session(state)

    if not session:
        return error_page("Invalid Session", "This gateway session is invalid.")

    if session.get("used") and session.get("shortener_url"):
        return RedirectResponse(
            url=session["shortener_url"],
            status_code=302,
        )

    return error_page(
        "Verification Required",
        "Please start from the original bot gateway link.",
    )


# =========================================================
# DEBUG SESSION
# =========================================================

@app.get("/api/session")
def debug_session(state: str = Query("")):
    if not state:
        return JSONResponse(
            {"ok": False, "error": "state is required"},
            status_code=400,
        )

    session = get_session(state)

    if not session:
        return JSONResponse(
            {"ok": False, "error": "session not found"},
            status_code=404,
        )

    safe = dict(session)
    safe.pop("browser_hash", None)
    safe.pop("challenge_hash", None)
    safe.pop("shortener_url", None)

    return JSONResponse({"ok": True, "session": safe})
