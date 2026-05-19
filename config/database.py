"""
Database configuration and connection management
"""

import os
import time
from pymongo import MongoClient
from typing import Optional
from utils.logger import get_logger

logger = get_logger(__name__)

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/reconx_db")

MAX_RETRIES = 3
RETRY_DELAY = 2
CONNECTION_TIMEOUT = 10000

import functools
from pymongo.errors import AutoReconnect, ServerSelectionTimeoutError, ConnectionFailure

def retry_mongo_op(max_retries=5, initial_delay=0.5, backoff=2.0):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            delay = initial_delay
            last_exc = None
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except (AutoReconnect, ServerSelectionTimeoutError, ConnectionFailure) as e:
                    last_exc = e
                    logger.warning(
                        f"MongoDB transient error in {func.__name__} (attempt {attempt+1}/{max_retries}): {e}. "
                        f"Retrying in {delay:.1f}s..."
                    )
                    time.sleep(delay)
                    delay *= backoff
            logger.error(f"MongoDB operation {func.__name__} failed permanently after {max_retries} attempts.")
            raise last_exc
        return wrapper
    return decorator

class RetryCollectionWrapper:
    def __init__(self, collection):
        self._collection = collection

    def __getattr__(self, name):
        attr = getattr(self._collection, name)
        if name.startswith('_'):
            return attr
        if callable(attr):
            return retry_mongo_op()(attr)
        return attr

    def __getitem__(self, item):
        return self._collection[item]

    def __repr__(self):
        return repr(self._collection)

class RetryDatabaseWrapper:
    def __init__(self, db_obj):
        self._db = db_obj

    def __getattr__(self, name):
        attr = getattr(self._db, name)
        from pymongo.collection import Collection
        if isinstance(attr, Collection):
            return RetryCollectionWrapper(attr)
        if callable(attr):
            return retry_mongo_op()(attr)
        return attr

    def __getitem__(self, name):
        col = self._db[name]
        return RetryCollectionWrapper(col)

    def __repr__(self):
        return repr(self._db)

client: Optional[MongoClient] = None
db = None

users_collection = None
domains_collection = None
reports_collection = None
user_logs_collection = None
subdomains_collection = None
technologies_collection = None
vulnerabilities_collection = None
anomalies_collection = None   # 🔥 REQUIRED
recommendations_collection = None  # Model 7
audit_logs_collection = None  # Audit Logs (tamper-resistant)
crawled_endpoints_collection = None  # Model 3 crawling extension


def connect_mongodb():
    global client, db
    global users_collection, domains_collection, reports_collection
    global user_logs_collection, subdomains_collection
    global technologies_collection, vulnerabilities_collection
    global anomalies_collection, recommendations_collection
    global audit_logs_collection, crawled_endpoints_collection

    for attempt in range(MAX_RETRIES):
        try:
            logger.info(f"Connecting to MongoDB (attempt {attempt+1})")

            client = MongoClient(
                MONGO_URI,
                serverSelectionTimeoutMS=CONNECTION_TIMEOUT,
                connectTimeoutMS=CONNECTION_TIMEOUT,
                socketTimeoutMS=CONNECTION_TIMEOUT
            )

            client.server_info()
            logger.info("MongoDB connected successfully")

            db = RetryDatabaseWrapper(client["reconx_db"])

            users_collection = db["users"]
            domains_collection = db["domains"]
            reports_collection = db["reports"]
            user_logs_collection = db["user_logs"]
            subdomains_collection = db["subdomains"]
            technologies_collection = db["technologies"]
            vulnerabilities_collection = db["vulnerabilities"]
            anomalies_collection = db["anomalies"]  # Model 4
            recommendations_collection = db["recommendations"]  # Model 7
            audit_logs_collection = db["audit_logs"]  # Audit Logs
            crawled_endpoints_collection = db["crawled_endpoints"]  # Model 3 crawling

            # ── Create indexes for query performance ──
            try:
                users_collection.create_index("email", unique=True)
                reports_collection.create_index([("user_id", 1), ("scanned_at", -1)])
                reports_collection.create_index([("domain", 1), ("scanned_at", -1)])
                subdomains_collection.create_index([("domain", 1), ("subdomain", 1)])
                technologies_collection.create_index([("domain", 1), ("subdomain", 1)])
                anomalies_collection.create_index([("domain", 1), ("subdomain", 1)])
                crawled_endpoints_collection.create_index([("domain", 1), ("subdomain", 1)])
                audit_logs_collection.create_index([("timestamp", -1)])
                audit_logs_collection.create_index("action")
                logger.info("MongoDB indexes ensured")
            except Exception as e:
                logger.warning(f"Index creation error (non-fatal): {e}")

            return True

        except Exception as e:
            logger.error(f"MongoDB error: {e}")
            time.sleep(RETRY_DELAY)

    logger.warning("MongoDB OFFLINE — using dummy collections")
    _init_dummy_collections()
    return False


def _init_dummy_collections():
    global users_collection, domains_collection, reports_collection
    global user_logs_collection, subdomains_collection
    global technologies_collection, vulnerabilities_collection
    global anomalies_collection, recommendations_collection
    global audit_logs_collection, crawled_endpoints_collection

    class DummyCollection:
        def find_one(self, *a, **k): return None
        def find(self, *a, **k): return []
        def insert_one(self, *a, **k): return None
        def update_one(self, *a, **k): return None
        def delete_one(self, *a, **k): return None

    users_collection = DummyCollection()
    domains_collection = DummyCollection()
    reports_collection = DummyCollection()
    user_logs_collection = DummyCollection()
    subdomains_collection = DummyCollection()
    technologies_collection = DummyCollection()
    vulnerabilities_collection = DummyCollection()
    anomalies_collection = DummyCollection()   # 🔥 REQUIRED
    recommendations_collection = DummyCollection()
    audit_logs_collection = DummyCollection()
    crawled_endpoints_collection = DummyCollection()


def is_mongodb_connected():
    if not client:
        return False
    try:
        client.server_info()
        return True
    except:
        return False
