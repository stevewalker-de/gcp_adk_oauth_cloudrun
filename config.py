# config.py
import os

GCP_PROJECT = os.getenv("GCP_PROJECT", "g-sql-morphic-luminous")
_DEFAULT_PROD_URL = "https://simple-oauth-app-732814971409.us-central1.run.app"
_LOCAL_URL = "http://localhost:8501"

REDIRECT_URI = os.getenv("REDIRECT_URI")
if not REDIRECT_URI:
    if os.getenv("K_SERVICE"):
        REDIRECT_URI = _DEFAULT_PROD_URL
    else:
        REDIRECT_URI = _LOCAL_URL

LOCATION = "global"
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_APPLICATION_CREDENTIALS = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
GCS_INPUT_BUCKET = os.getenv("GCS_INPUT_BUCKET")
MODEL_NAME = "gemini-3-flash-preview"
COOKIE_MANAGER_SECRET = "cookie_manager_secret"

# Firestore & Auth Config
FIRESTORE_DATABASE = "tcoapp"
FIRESTORE_TOKEN_COLLECTION = "Tessera_Homōnis"
ALLOWED_DOMAIN = "google.com"

GOOGLE_API_SCOPES = [
    "https://www.googleapis.com/auth/cloud-platform",  # Added for general auth
]

OAUTH_SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email"
]
