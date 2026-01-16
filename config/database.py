"""
Database configuration and connection management
"""

import os
import time
from pymongo import MongoClient
from typing import Optional

MONGO_URI = os.getenv(
    "MONGO_URI",
    "mongodb+srv://youssef2203723_db_user:SQmEU8rJv4amXR38@cluster0.tfybtes.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
)

MAX_RETRIES = 3
RETRY_DELAY = 2
CONNECTION_TIMEOUT = 10000

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


def connect_mongodb():
    global client, db
    global users_collection, domains_collection, reports_collection
    global user_logs_collection, subdomains_collection
    global technologies_collection, vulnerabilities_collection
    global anomalies_collection

    for attempt in range(MAX_RETRIES):
        try:
            print(f"[DB] Connecting (attempt {attempt+1})")

            client = MongoClient(
                MONGO_URI,
                serverSelectionTimeoutMS=CONNECTION_TIMEOUT,
                connectTimeoutMS=CONNECTION_TIMEOUT,
                socketTimeoutMS=CONNECTION_TIMEOUT
            )

            client.server_info()
            print("✅ MongoDB connected")

            db = client["reconx_db"]

            users_collection = db["users"]
            domains_collection = db["domains"]
            reports_collection = db["reports"]
            user_logs_collection = db["user_logs"]
            subdomains_collection = db["subdomains"]
            technologies_collection = db["technologies"]
            vulnerabilities_collection = db["vulnerabilities"]
            anomalies_collection = db["anomalies"]  # 🔥 MODEL 4

            return True

        except Exception as e:
            print(f"❌ MongoDB error: {e}")
            time.sleep(RETRY_DELAY)

    print("⚠️ MongoDB OFFLINE — using dummy collections")
    _init_dummy_collections()
    return False


def _init_dummy_collections():
    global users_collection, domains_collection, reports_collection
    global user_logs_collection, subdomains_collection
    global technologies_collection, vulnerabilities_collection
    global anomalies_collection

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


def is_mongodb_connected():
    if not client:
        return False
    try:
        client.server_info()
        return True
    except:
        return False
