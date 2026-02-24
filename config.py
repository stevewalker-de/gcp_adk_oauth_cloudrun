# config.py
import os
from enum import Enum

GCP_PROJECT = "g-sql-morphic-luminous"
REDIRECT_URI = "https://simple-oauth-app-732814971409.us-central1.run.app"

LOCATION = "global"
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_APPLICATION_CREDENTIALS = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
GCS_INPUT_BUCKET = os.getenv("GCS_INPUT_BUCKET")
MODEL_NAME = "gemini-3-flash-preview"


GOOGLE_API_SCOPES = [
    "https://www.googleapis.com/auth/cloud-platform",  # Added for general auth
]

OAUTH_SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email"
]
