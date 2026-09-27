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

BOT_USERNAME = os.getenv(
    "BOT_USERNAME",
    ""
).replace("@", "").strip()

BOT2_USERNAME = os.getenv(
    "BOT2_USERNAME",
    ""
).replace("@", "").strip()

MONGO_URI = os.getenv(
    "MONGO_URI",
    ""
).strip()

MONGO_DB = os.getenv(
    "MONGO_DB",
    "file_store_bot"
).strip()


# =========================================================
# UNIVERSAL SHORTENER
# =========================================================

SHORTENER_API_URL = os.getenv(
    "SHORTENER_API_URL",
    ""
).strip().rstrip("/")

SHORTENER_API_KEY = os.getenv(
    "SHORTENER_API_KEY",
    ""
).strip()


# Legacy VPLink fallback
if not SHORTENER_API_URL:
    SHORTENER_API_URL = os.getenv(
        "VPLINK_API_URL",
        "https://vplink.in/api"
    ).strip().rstrip("/")


if not SHORTENER_API_KEY:
    SHORTENER_API_KEY = os.getenv(
        "VPLINK_API_KEY",
        ""
    ).strip()


GATEWAY_DOMAIN = os.getenv(
    "GATEWAY_DOMAIN",
    "https://lozo-94.vercel.app"
).strip().rstrip("/")


SESSION_MINUTES = int(
    os.getenv(
        "SESSION_MINUTES",
        "30"
    )
)


VERIFY_MINUTES = int(
    os.getenv(
        "VERIFY_MINUTES",
        "10"
    )
)


# =========================================================
# APP / LOGGING
# =========================================================

app = FastAPI()

logging.basicConfig(
    level=logging.INFO
)

logger = logging.getLogger(
    "lozo-gateway"
)


# =========================================================
# DATABASE
# =========================================================

mongo = None
db = None
DB_ERROR = None


def initialize_database():

    global mongo
    global db
    global DB_ERROR

    DB_ERROR = None

    if not MONGO_URI:

        DB_ERROR = "MONGO_URI is not configured"

        logger.error(
            DB_ERROR
        )

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

        # -------------------------------------------------
        # TOKEN COLLECTIONS
        # -------------------------------------------------

        token_collections = [
            "bot_bot1_tokens",
            "bot_bot2_tokens",
            "tokens",
        ]

        for collection_name in token_collections:

            collection = db[collection_name]

            try:

                indexes = {
                    idx["name"]: idx
                    for idx in collection.list_indexes()
                }

                token_index = indexes.get(
                    "token_1"
                )

                if token_index:

                    if not token_index.get(
                        "unique",
                        False
                    ):

                        collection.drop_index(
                            "token_1"
                        )

                        collection.create_index(
                            [("token", ASCENDING)],
                            name="token_1",
                            unique=True
                        )

                else:

                    collection.create_index(
                        [("token", ASCENDING)],
                        name="token_1",
                        unique=True
                    )

            except Exception as e:

                logger.warning(
                    "Token index check failed for %s: %s",
                    collection_name,
                    e
                )

        # -------------------------------------------------
        # GATEWAY STATE INDEX
        # -------------------------------------------------

        indexes = {
            idx["name"]: idx
            for idx in db.gateway_states.list_indexes()
        }

        state_index = indexes.get(
            "state_1"
        )

        if state_index:

            if not state_index.get(
                "unique",
                False
            ):

                db.gateway_states.drop_index(
                    "state_1"
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

        # -------------------------------------------------
        # GATEWAY STATE TOKEN INDEX
        #
        # Multiple sessions can use same original token.
        # -------------------------------------------------

        indexes = {
            idx["name"]: idx
            for idx in db.gateway_states.list_indexes()
        }

        token_index = indexes.get(
            "token_1"
        )

        if token_index:

            if token_index.get(
                "unique",
                False
            ):

                db.gateway_states.drop_index(
                    "token_1"
                )

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

        # -------------------------------------------------
        # REMOVE OLD CHALLENGE HASH INDEX
        # -------------------------------------------------

        indexes = {
            idx["name"]: idx
            for idx in db.gateway_states.list_indexes()
        }

        if "challenge_hash_1" in indexes:

            db.gateway_states.drop_index(
                "challenge_hash_1"
            )

        # -------------------------------------------------
        # ONE-TIME GATEWAY ENTRIES
        #
        # shortener.py creates one entry for every
        # generated gateway link.
        #
        # The original Telegram token remains reusable.
        # -------------------------------------------------

        db.gateway_entries.create_index(
            [("entry_id", ASCENDING)],
            name="entry_id_1",
            unique=True
        )

        db.gateway_entries.create_index(
            [("token", ASCENDING)],
            name="gateway_entry_token_1",
            unique=False
        )

        db.gateway_entries.create_index(
            [("created_at", ASCENDING)],
            name="gateway_entry_created_at_1",
            unique=False
        )

        logger.info(
            "MongoDB connected successfully: %s",
            MONGO_DB
        )

        return True

    except Exception as e:

        DB_ERROR = (
            f"{type(e).__name__}: {str(e)}"
        )

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
# BOT / TOKEN HELPERS
# =========================================================

def get_token_record(token):

    if not db_ready():
        return None

    # -----------------------------------------------------
    # Bot 1
    # -----------------------------------------------------

    try:

        record = db.bot_bot1_tokens.find_one(
            {"token": token},
            {"_id": 0}
        )

        if record:

            record["_gateway_bot_id"] = "bot1"

            return record

    except Exception as e:

        logger.warning(
            "Bot 1 token lookup failed: %s",
            e
        )

    # -----------------------------------------------------
    # Bot 2
    # -----------------------------------------------------

    try:

        record = db.bot_bot2_tokens.find_one(
            {"token": token},
            {"_id": 0}
        )

        if record:

            record["_gateway_bot_id"] = "bot2"

            return record

    except Exception as e:

        logger.warning(
            "Bot 2 token lookup failed: %s",
            e
        )

    # -----------------------------------------------------
    # Legacy
    # -----------------------------------------------------

    try:

        record = db.tokens.find_one(
            {"token": token},
            {"_id": 0}
        )

        if record:

            record["_gateway_bot_id"] = (
                record.get("bot_id")
                or "bot1"
            )

            return record

    except Exception as e:

        logger.warning(
            "Legacy token lookup failed: %s",
            e
        )

    return None


def get_bot_username(bot_id):

    bot_id = str(
        bot_id or "bot1"
    ).strip().lower()

    if bot_id == "bot2":
        return BOT2_USERNAME

    return BOT_USERNAME


# =========================================================
# ERROR PAGE
# =========================================================

def error_page(
    title,
    message
):

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

<h1>
{html.escape(title)}
</h1>

<p>
{html.escape(message)}
</p>

<div class="brand">
Lozo Gateway
</div>

</div>

</body>
</html>
""",
        status_code=400
    )


# =========================================================
# ONE-TIME GATEWAY MESSAGE
# =========================================================

def already_used_page():

    return error_page(
        "This Link Is Already Used",
        "This Link Is Already Used. Please Generate Another From The Channel"
    )


# =========================================================
# DATABASE HELPERS
# =========================================================

def get_session(state):

    if not db_ready():
        return None

    return db.gateway_states.find_one(
        {"state": state},
        {"_id": 0}
    )


def get_session_by_verify_id(
    verify_id
):

    if not db_ready():
        return None

    return db.gateway_states.find_one(
        {"verify_id": verify_id},
        {"_id": 0}
    )


def save_session(session):

    if not db_ready():
        return False

    db.gateway_states.insert_one(
        session
    )

    return True


def update_session(
    state,
    update
):

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
# UNIVERSAL SHORTENER
# =========================================================

PROVIDER_NAMES = (
    "vplink",
    "vplinks",
    "arolinks",
    "shortxlinks",
    "instantlinks",
    "rempo",
    "remso",
    "babylinks",
    "linkshortify",
    "bitly",
    "rebrandly",
    "short.io",
    "shortio",
    "shrinkme",
)


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


def shortener_provider():

    value = (
        SHORTENER_API_URL
        or ""
    ).lower()

    for name in PROVIDER_NAMES:

        if name in value:
            return name

    return "generic"


def extract_short_url(data):

    if isinstance(
        data,
        str
    ):

        value = data.strip()

        if value.startswith(
            "http://"
        ) or value.startswith(
            "https://"
        ):

            return value

        return None

    if isinstance(
        data,
        dict
    ):

        for key in SHORT_URL_KEYS:

            value = data.get(
                key
            )

            if isinstance(
                value,
                str
            ):

                value = value.strip()

                if value.startswith(
                    "http://"
                ) or value.startswith(
                    "https://"
                ):

                    return value

        for key in (
            "result",
            "data",
            "response",
            "link",
            "resultData",
        ):

            nested = data.get(
                key
            )

            result = extract_short_url(
                nested
            )

            if result:
                return result

    if isinstance(
        data,
        list
    ):

        for item in data:

            result = extract_short_url(
                item
            )

            if result:
                return result

    return None


def parse_shortener_response(
    response
):

    if not response.ok:

        logger.warning(
            "Shortener HTTP %s: %s",
            response.status_code,
            response.text[:500]
        )

        return None

    try:

        data = response.json()

        result = extract_short_url(
            data
        )

        if result:
            return result

    except Exception:
        pass

    text = response.text.strip()

    if text.startswith(
        "http://"
    ) or text.startswith(
        "https://"
    ):

        return text

    return None


def unique_endpoints():

    base = (
        SHORTENER_API_URL
        or ""
    ).rstrip("/")

    values = [

        base,

        f"{base}/shorten",

        f"{base}/create",

        f"{base}/api/shorten",

        f"{base}/api/create",

        f"{base}/api/v1/shorten",

        f"{base}/api/v1/shorten/",
    ]

    result = []

    for value in values:

        if value and value not in result:
            result.append(value)

    return result


def create_bitly(
    destination
):

    headers = {
        "Authorization":
            f"Bearer {SHORTENER_API_KEY}",
        "Content-Type":
            "application/json",
    }

    payload = {
        "long_url": destination
    }

    try:

        response = requests.post(
            "https://api-ssl.bitly.com/v4/shorten",
            headers=headers,
            json=payload,
            timeout=20
        )

        if response.ok:

            data = response.json()

            result = (
                data.get("link")
                or data.get("url")
            )

            if result:
                return result

    except Exception as e:

        logger.warning(
            "Bitly failed: %s",
            e
        )

    return None


def create_rebrandly(
    destination
):

    headers = {
        "apikey":
            SHORTENER_API_KEY,
        "Content-Type":
            "application/json",
    }

    payload = {
        "destination": destination
    }

    try:

        response = requests.post(
            "https://api.rebrandly.com/v1/links",
            headers=headers,
            json=payload,
            timeout=20
        )

        if response.ok:

            data = response.json()

            short_url = extract_short_url(
                data
            )

            if short_url:
                return short_url

            short = data.get(
                "shortUrl"
            )

            if short:

                return (
                    "https://"
                    + str(short).lstrip("/")
                )

    except Exception as e:

        logger.warning(
            "Rebrandly failed: %s",
            e
        )

    return None


def create_shortio(
    destination
):

    headers = {
        "Authorization":
            SHORTENER_API_KEY,
        "Content-Type":
            "application/json",
    }

    payload = {
        "originalURL": destination
    }

    try:

        response = requests.post(
            "https://api.short.io/links",
            headers=headers,
            json=payload,
            timeout=20
        )

        if response.ok:

            data = response.json()

            result = extract_short_url(
                data
            )

            if result:
                return result

            domain = data.get(
                "shortURL"
            )

            if domain:
                return domain

    except Exception as e:

        logger.warning(
            "Short.io failed: %s",
            e
        )

    return None


def create_generic_shortener(
    destination
):

    endpoints = unique_endpoints()

    # -----------------------------------------------------
    # GET
    # -----------------------------------------------------

    get_parameters = [

        {
            "api": SHORTENER_API_KEY,
            "url": destination,
        },

        {
            "api_key": SHORTENER_API_KEY,
            "url": destination,
        },

        {
            "key": SHORTENER_API_KEY,
            "url": destination,
        },

        {
            "token": SHORTENER_API_KEY,
            "url": destination,
        },

        {
            "apikey": SHORTENER_API_KEY,
            "url": destination,
        },

        {
            "api": SHORTENER_API_KEY,
            "link": destination,
        },

        {
            "api_key": SHORTENER_API_KEY,
            "link": destination,
        },

        {
            "key": SHORTENER_API_KEY,
            "link": destination,
        },
    ]

    for endpoint in endpoints:

        for params in get_parameters:

            try:

                logger.info(
                    "Shortener GET: %s",
                    endpoint
                )

                response = requests.get(
                    endpoint,
                    params=params,
                    timeout=20
                )

                result = parse_shortener_response(
                    response
                )

                if result:
                    return result

            except Exception as e:

                logger.warning(
                    "Shortener GET failed: %s",
                    e
                )

    # -----------------------------------------------------
    # POST JSON
    # -----------------------------------------------------

    post_payloads = [

        {
            "url": destination,
            "api": SHORTENER_API_KEY,
        },

        {
            "url": destination,
            "api_key": SHORTENER_API_KEY,
        },

        {
            "url": destination,
            "key": SHORTENER_API_KEY,
        },

        {
            "link": destination,
            "api": SHORTENER_API_KEY,
        },

        {
            "link": destination,
            "api_key": SHORTENER_API_KEY,
        },

        {
            "originalURL": destination,
            "api": SHORTENER_API_KEY,
        },

        {
            "long_url": destination,
            "api": SHORTENER_API_KEY,
        },

        {
            "destination": destination,
            "api": SHORTENER_API_KEY,
        },
    ]

    for endpoint in endpoints:

        for payload in post_payloads:

            try:

                logger.info(
                    "Shortener POST JSON: %s",
                    endpoint
                )

                response = requests.post(
                    endpoint,
                    json=payload,
                    timeout=20
                )

                result = parse_shortener_response(
                    response
                )

                if result:
                    return result

            except Exception as e:

                logger.warning(
                    "Shortener POST JSON failed: %s",
                    e
                )

    # -----------------------------------------------------
    # POST FORM
    # -----------------------------------------------------

    for endpoint in endpoints:

        for payload in post_payloads:

            try:

                response = requests.post(
                    endpoint,
                    data=payload,
                    timeout=20
                )

                result = parse_shortener_response(
                    response
                )

                if result:
                    return result

            except Exception as e:

                logger.warning(
                    "Shortener POST form failed: %s",
                    e
                )

    return None


def create_shortener_link(
    destination
):

    if not SHORTENER_API_URL:

        logger.error(
            "SHORTENER_API_URL is missing"
        )

        return None

    if not SHORTENER_API_KEY:

        logger.error(
            "SHORTENER_API_KEY is missing"
        )

        return None

    provider = shortener_provider()

    logger.info(
        "Using shortener provider: %s",
        provider
    )

    # -----------------------------------------------------
    # BITLY
    # -----------------------------------------------------

    if provider == "bitly":

        result = create_bitly(
            destination
        )

        if result:
            return result

    # -----------------------------------------------------
    # REBRANDLY
    # -----------------------------------------------------

    if provider == "rebrandly":

        result = create_rebrandly(
            destination
        )

        if result:
            return result

    # -----------------------------------------------------
    # SHORT.IO
    # -----------------------------------------------------

    if provider in (
        "short.io",
        "shortio",
    ):

        result = create_shortio(
            destination
        )

        if result:
            return result

    # -----------------------------------------------------
    # GENERIC
    # -----------------------------------------------------

    result = create_generic_shortener(
        destination
    )

    if result:
        return result

    logger.error(
        "Unable to create shortener link"
    )

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

<title>
Lozo Gateway
</title>

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

<h1>
Lozo Gateway
</h1>

<p>
Secure gateway is active.
</p>

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

        "service":
            "lozo-gateway",

        "database":
            db_ready(),

        "shortener":
            bool(
                SHORTENER_API_URL
                and SHORTENER_API_KEY
            ),

        "token_namespaces": [
            "bot_bot1_tokens",
            "bot_bot2_tokens",
            "tokens",
        ],

        "gateway_entries":
            db_ready(),
    }

    return JSONResponse(
        result
    )


# =========================================================
# GATEWAY
# =========================================================

@app.get("/api/gateway")
def gateway(
    request: Request,
    entry: str = Query("")
):

    entry = entry.strip()

    if not entry:

        return error_page(
            "Invalid Link",
            "No gateway entry was provided."
        )

    if not db_ready():

        return error_page(
            "Database Error",
            "Gateway database is unavailable."
        )

    # -----------------------------------------------------
    # FIND UNIQUE GATEWAY ENTRY
    # -----------------------------------------------------

    gateway_entry = db.gateway_entries.find_one(
        {
            "entry_id": entry
        },
        {
            "_id": 0
        }
    )

    if not gateway_entry:

        return error_page(
            "Invalid Link",
            "This gateway link is invalid or no longer available."
        )

    # -----------------------------------------------------
    # EXACT GENERATED URL ALREADY USED
    # -----------------------------------------------------

    if gateway_entry.get(
        "used"
    ) is True:

        return already_used_page()

    # -----------------------------------------------------
    # ORIGINAL TOKEN
    # -----------------------------------------------------

    original_token = str(
        gateway_entry.get(
            "token"
        )
        or ""
    ).strip()

    if not original_token:

        return error_page(
            "Invalid Link",
            "Original token is missing."
        )

    # -----------------------------------------------------
    # ORIGINAL TOKEN VALIDATION
    #
    # The original token is ONLY checked.
    #
    # It is never consumed here.
    # -----------------------------------------------------

    token_record = get_token_record(
        original_token
    )

    if not token_record:

        return error_page(
            "Invalid Link",
            "This link is invalid or no longer available."
        )

    # -----------------------------------------------------
    # TOKEN EXPIRY
    # -----------------------------------------------------

    now = datetime.now(
        timezone.utc
    )

    token_expiry = token_record.get(
        "expires_at"
    )

    if token_expiry:

        if token_expiry.tzinfo is None:

            token_expiry = (
                token_expiry.replace(
                    tzinfo=timezone.utc
                )
            )

        if token_expiry <= now:

            return error_page(
                "Link Expired",
                "This file link has expired."
            )

    # -----------------------------------------------------
    # BOT
    # -----------------------------------------------------

    bot_id = (
        token_record.get(
            "_gateway_bot_id"
        )
        or token_record.get(
            "bot_id"
        )
        or "bot1"
    )

    bot_username = (
        gateway_entry.get(
            "bot_username"
        )
        or get_bot_username(
            bot_id
        )
    )

    if not bot_username:

        return error_page(
            "Configuration Error",
            f"Bot username for {bot_id} is not configured."
        )

    # -----------------------------------------------------
    # BROWSER
    # -----------------------------------------------------

    browser_id = request.cookies.get(
        "lozo_browser_id"
    )

    set_browser_cookie = False

    if not browser_id:

        browser_id = secrets.token_urlsafe(
            32
        )

        set_browser_cookie = True

    browser_hash = hashlib.sha256(
        browser_id.encode()
    ).hexdigest()

    # -----------------------------------------------------
    # NEW SESSION
    # -----------------------------------------------------

    state = secrets.token_urlsafe(
        32
    )

    access_id = secrets.token_urlsafe(
        24
    )

    expires_at = (
        now
        + timedelta(
            minutes=SESSION_MINUTES
        )
    )

    session = {

        "state":
            state,

        "access_id":
            access_id,

        "entry_id":
            entry,

        "token":
            original_token,

        "bot_id":
            bot_id,

        "bot_username":
            bot_username,

        "browser_hash":
            browser_hash,

        "created_at":
            now,

        "expires_at":
            expires_at,

        "opened":
            False,

        "used":
            False,

        "verified":
            False,
    }

    # -----------------------------------------------------
    # SAVE SESSION
    # -----------------------------------------------------

    try:

        save_session(
            session
        )

    except Exception as e:

        logger.error(
            "Unable to save gateway session: %s",
            e
        )

        return error_page(
            "Gateway Error",
            "Unable to create gateway session."
        )

    # -----------------------------------------------------
    # COMPLETE URL
    # -----------------------------------------------------

    complete_url = (
        f"{GATEWAY_DOMAIN}/api/complete?"
        + urlencode(
            {
                "state":
                    state
            }
        )
    )

    # -----------------------------------------------------
    # UNIVERSAL SHORTENER
    # -----------------------------------------------------

    shortener_url = create_shortener_link(
        complete_url
    )

    if not shortener_url:

        delete_session(
            state
        )

        return error_page(
            "Gateway Error",
            "Unable to create gateway link. Please try again."
        )

    update_session(
        state,
        {
            "shortener_url":
                shortener_url,

            "vplink_url":
                shortener_url,
        }
    )

    # -----------------------------------------------------
    # ATOMICALLY CONSUME ONLY THIS ENTRY
    #
    # The original Telegram token is NOT changed.
    #
    # Only:
    #
    # gateway_entries.used = True
    #
    # Therefore:
    #
    # Same entry -> one time
    # New entry from same token -> works normally
    # -----------------------------------------------------

    claim_result = db.gateway_entries.update_one(
        {
            "entry_id":
                entry,

            "used":
                False,
        },
        {
            "$set": {
                "used":
                    True,

                "used_at":
                    now,
            }
        }
    )

    if claim_result.modified_count != 1:

        delete_session(
            state
        )

        return already_used_page()

    # -----------------------------------------------------
    # ACCESS
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
        {
            "access_id":
                access_id
        },
        {
            "_id": 0
        }
    )

    if not session:

        return error_page(
            "Invalid Session",
            "This gateway session is invalid."
        )

    now = datetime.now(
        timezone.utc
    )

    # -----------------------------------------------------
    # SESSION EXPIRY
    # -----------------------------------------------------

    expires_at = session.get(
        "expires_at"
    )

    if expires_at:

        if expires_at.tzinfo is None:

            expires_at = (
                expires_at.replace(
                    tzinfo=timezone.utc
                )
            )

        if expires_at <= now:

            return error_page(
                "Session Expired",
                "This gateway session has expired."
            )

    # -----------------------------------------------------
    # ALREADY OPENED
    # -----------------------------------------------------

    if session.get(
        "opened"
    ):

        return already_used_page()

    # -----------------------------------------------------
    # BROWSER
    # -----------------------------------------------------

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

    # -----------------------------------------------------
    # ATOMIC ONE-TIME OPEN
    # -----------------------------------------------------

    result = db.gateway_states.update_one(
        {
            "access_id":
                access_id,

            "opened":
                False,
        },
        {
            "$set": {
                "opened":
                    True,

                "opened_at":
                    now,
            }
        }
    )

    if result.modified_count != 1:

        return already_used_page()

    # -----------------------------------------------------
    # SHORTENER
    # -----------------------------------------------------

    shortener_url = (
        session.get(
            "shortener_url"
        )
        or session.get(
            "vplink_url"
        )
    )

    if not shortener_url:

        return error_page(
            "Gateway Error",
            "Gateway destination is unavailable."
        )

    escaped_url = html.escape(
        shortener_url,
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

<title>
Lozo Gateway
</title>

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

<h2>
Redirecting...
</h2>

<p>
Please wait...
</p>

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

    session = get_session(
        state
    )

    if not session:

        return error_page(
            "Invalid Session",
            "This gateway session is invalid."
        )

    # -----------------------------------------------------
    # GATEWAY MUST HAVE BEEN OPENED
    # -----------------------------------------------------

    if session.get(
        "opened"
    ) is not True:

        return error_page(
            "Invalid Session",
            "This gateway session has not been opened correctly."
        )

    # -----------------------------------------------------
    # DELIVERY ALREADY COMPLETED
    # -----------------------------------------------------

    if session.get(
        "used"
    ):

        return already_used_page()

    now = datetime.now(
        timezone.utc
    )

    expires_at = session.get(
        "expires_at"
    )

    if expires_at:

        if expires_at.tzinfo is None:

            expires_at = (
                expires_at.replace(
                    tzinfo=timezone.utc
                )
            )

        if expires_at <= now:

            return error_page(
                "Session Expired",
                "This gateway session has expired."
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

    if session.get(
        "verified"
    ):

        return RedirectResponse(
            url=(
                f"/api/deliver?"
                f"state={state}"
            ),
            status_code=302
        )

    # -----------------------------------------------------
    # CREATE VERIFICATION
    # -----------------------------------------------------

    verify_id = secrets.token_urlsafe(
        32
    )

    challenge = secrets.token_urlsafe(
        32
    )

    challenge_hash = hashlib.sha256(
        challenge.encode()
    ).hexdigest()

    verify_expires_at = (
        now
        + timedelta(
            minutes=VERIFY_MINUTES
        )
    )

    update_session(
        state,
        {
            "verify_id":
                verify_id,

            "challenge_hash":
                challenge_hash,

            "verify_expires_at":
                verify_expires_at,
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

<title>
Verification
</title>

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

<h1>
Verification Required
</h1>

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

    # -----------------------------------------------------
    # DELIVERY ALREADY USED
    # -----------------------------------------------------

    if session.get(
        "used"
    ):

        return already_used_page()

    now = datetime.now(
        timezone.utc
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

        verify_expires_at = (
            verify_expires_at.replace(
                tzinfo=timezone.utc
            )
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

    if (
        not challenge
        or actual_hash != expected_hash
    ):

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
            "verified":
                True,

            "verified_at":
                now,
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

    session = get_session(
        state
    )

    if not session:

        return error_page(
            "Invalid Session",
            "This gateway session is invalid."
        )

    # -----------------------------------------------------
    # GATEWAY MUST HAVE BEEN OPENED
    # -----------------------------------------------------

    if session.get(
        "opened"
    ) is not True:

        return error_page(
            "Invalid Session",
            "This gateway session has not been opened correctly."
        )

    # -----------------------------------------------------
    # ALREADY USED
    # -----------------------------------------------------

    if session.get(
        "used"
    ):

        return already_used_page()

    now = datetime.now(
        timezone.utc
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
    # SESSION EXPIRY
    # -----------------------------------------------------

    expires_at = session.get(
        "expires_at"
    )

    if expires_at:

        if expires_at.tzinfo is None:

            expires_at = (
                expires_at.replace(
                    tzinfo=timezone.utc
                )
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

    if not session.get(
        "verified"
    ):

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

            verify_expires_at = (
                verify_expires_at.replace(
                    tzinfo=timezone.utc
                )
            )

        if verify_expires_at <= now:

            return error_page(
                "Verification Expired",
                "Please start the gateway again."
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

    # -----------------------------------------------------
    # TOKEN EXPIRY
    # -----------------------------------------------------

    token_expiry = token_record.get(
        "expires_at"
    )

    if token_expiry:

        if token_expiry.tzinfo is None:

            token_expiry = (
                token_expiry.replace(
                    tzinfo=timezone.utc
                )
            )

        if token_expiry <= now:

            return error_page(
                "Link Expired",
                "This file link has expired."
            )

    # -----------------------------------------------------
    # BOT
    # -----------------------------------------------------

    bot_id = (
        session.get(
            "bot_id"
        )
        or token_record.get(
            "_gateway_bot_id"
        )
        or token_record.get(
            "bot_id"
        )
        or "bot1"
    )

    bot_username = (
        session.get(
            "bot_username"
        )
        or get_bot_username(
            bot_id
        )
    )

    if not bot_username:

        return error_page(
            "Configuration Error",
            f"Bot username for {bot_id} is not configured."
        )

    # -----------------------------------------------------
    # ATOMIC DELIVERY USE
    #
    # Only this gateway session is consumed.
    #
    # Original Telegram token remains reusable.
    # -----------------------------------------------------

    result = db.gateway_states.update_one(
        {
            "state":
                state,

            "used":
                False,
        },
        {
            "$set": {
                "used":
                    True,

                "delivered_at":
                    now,
            }
        }
    )

    if result.modified_count != 1:

        return already_used_page()

    # -----------------------------------------------------
    # TELEGRAM DELIVERY
    # -----------------------------------------------------

    telegram_url = (
        f"https://t.me/{bot_username}"
        f"?start=verify_{original_token}"
    )

    logger.info(
        "Gateway delivery: bot=%s username=%s",
        bot_id,
        bot_username
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

    response.delete_cookie(
        "lozo_shortener"
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
                "error":
                    "state is required"
            },
            status_code=400
        )

    session = get_session(
        state
    )

    if not session:

        return JSONResponse(
            {
                "ok": False,
                "error":
                    "session not found"
            },
            status_code=404
        )

    safe = dict(
        session
    )

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

    safe.pop(
        "shortener_url",
        None
    )

    return JSONResponse(
        {
            "ok": True,
            "session": safe
        }
    )
