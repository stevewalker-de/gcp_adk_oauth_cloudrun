import os
import streamlit as st
from streamlit_cookies_manager import (
    EncryptedCookieManager as SCMEncryptedCookieManager,
)
from app_secrets import get_secret
from config import GCP_PROJECT, COOKIE_MANAGER_SECRET


def get_cookie_manager(prefix: str = "tco_app/"):
    """
    Returns a cached instance of EncryptedCookieManager.
    """
    try:
        password = get_secret(GCP_PROJECT, COOKIE_MANAGER_SECRET)
    except Exception as e:
        # Fallback for local development or if Secret Manager is not reachable
        password = os.getenv("COOKIE_PASSWORD")
        if not password:
            st.warning(f"⚠️ Could not retrieve secret '{COOKIE_MANAGER_SECRET}' from Secret Manager and COOKIE_PASSWORD env var is not set. Using a fallback for local dev.")
            password = "local_dev_only_password_do_not_use_in_prod"

    return SCMEncryptedCookieManager(prefix=prefix, password=password)
