import os
import streamlit as st
from streamlit_cookies_manager import (
    EncryptedCookieManager as SCMEncryptedCookieManager,
)


def get_cookie_manager(prefix: str = "tco_app/"):
    """
    Returns a cached instance of EncryptedCookieManager.
    """
    # NOTE: In production, password should be a strong secret from env vars.
    password = os.getenv("COOKIE_PASSWORD", "xyz123abc!")  # Fallback for dev, TODO: Remove fallback
    if not password:
         raise ValueError("COOKIE_PASSWORD environment variable not set")
    return SCMEncryptedCookieManager(prefix=prefix, password=password)
