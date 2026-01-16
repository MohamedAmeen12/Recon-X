"""
Database configuration and connection management
"""
import os
import time
from pymongo import MongoClient
from typing import Optional

# MongoDB Connection String
MONGO_URI = os.getenv(
    "MONGO_URI",
    "mongodb+srv://youssef2203723_db_user:SQmEU8rJv4amXR38@cluster0.tfybtes.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
)

# Connection settings
MAX_RETRIES = 3
RETRY_DELAY = 2
CONNECTION_TIMEOUT = 10000

# Global client variable
client: Optional[MongoClient] = None
db = None
users_collection = None
domains_collection = None
reports_collection = None
user_logs_collection = None
subdomains_collection = None
technologies_collection = None
vulnerabilities_collection = None


def connect_mongodb():
    """Connect to MongoDB with retries."""
    global client, db, users_collection, domains_collection, reports_collection
    global user_logs_collection, subdomains_collection, technologies_collection
    global vulnerabilities_collection
    
    for attempt in range(MAX_RETRIES):
        try:
            print(f"Attempting MongoDB connection (attempt {attempt + 1}/{MAX_RETRIES})...")
            client = MongoClient(
                MONGO_URI,
                serverSelectionTimeoutMS=CONNECTION_TIMEOUT,
                connectTimeoutMS=CONNECTION_TIMEOUT,
                socketTimeoutMS=CONNECTION_TIMEOUT
            )
            client.server_info()
            print("✅ MongoDB connection successful!")
            time.sleep(RETRY_DELAY)

            
            # Initialize database and collections
            db = client["reconx_db"]
            users_collection = db["users"]
            domains_collection = db["domains"]
            reports_collection = db["reports"]
            user_logs_collection = db["user_logs"]
            subdomains_collection = db["subdomains"]
            technologies_collection = db["technologies"]
            vulnerabilities_collection = db["vulnerabilities"]
            
            return True
            
        except Exception as e:
            print(f"❌ MongoDB connection attempt {attempt + 1} failed: {e}")
            if attempt < MAX_RETRIES - 1:
                print(f"Retrying in {RETRY_DELAY} seconds...")
                time.sleep(RETRY_DELAY)
            else:
                print("\n" + "="*60)
                print("⚠️  WARNING: MongoDB connection failed after all retries!")
                print("="*60)
                print("Possible solutions:")
                print("1. Check your internet connection")
                print("2. Verify MongoDB Atlas cluster is running and not paused")
                print("3. Check if your IP address is whitelisted in MongoDB Atlas")
                print("4. Verify the connection string is correct")
                print("5. Check firewall settings")
                print("\nThe application will continue but database features will not work.")
                print("="*60 + "\n")
                _init_dummy_collections()
                return False
    
    return False


def _init_dummy_collections():
    """Initialize dummy collections for offline mode."""
    global users_collection, domains_collection, reports_collection
    global user_logs_collection, subdomains_collection, technologies_collection
    global vulnerabilities_collection
    
    class DummyCollection:
        def find_one(self, *args, **kwargs): return None
        def find(self, *args, **kwargs): return []
        def insert_one(self, *args, **kwargs): return None
        def update_one(self, *args, **kwargs): return None
        def delete_one(self, *args, **kwargs): return None
    
    users_collection = DummyCollection()
    domains_collection = DummyCollection()
    reports_collection = DummyCollection()
    user_logs_collection = DummyCollection()
    subdomains_collection = DummyCollection()
    technologies_collection = DummyCollection()
    vulnerabilities_collection = DummyCollection()


def is_mongodb_connected():
    """Check if MongoDB is connected and working."""
    if not client:
        return False
    try:
        client.server_info()
        return True
    except:
        return False


