import base64
import json
from typing import Dict, Optional, Any

import streamlit as st
from google.api_core.exceptions import GoogleAPICallError
from google.auth.transport.requests import Request
from google.cloud import firestore
from google.oauth2.credentials import Credentials

from app_secrets import get_secret
from config import (
    GCP_PROJECT, REDIRECT_URI, OAUTH_SCOPES,
    FIRESTORE_DATABASE, FIRESTORE_TOKEN_COLLECTION, ALLOWED_DOMAIN
)
from OAuth2Component import OAuth2Component

OAUTH_CLIENT_ID_SECRETMANAGER = "da-tco-app-clientid"
OAUTH_CLIENT_SECRET_SECRETMANAGER = "da-tco-app-clientsecret"

AUTHORIZE_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
REVOKE_ENDPOINT = "https://oauth2.googleapis.com/revoke"




class Authenticator:
    """
    Handles all authentication logic using Firestore and Streamlit cookies.
    """

    def __init__(self, cookies):
        """
        Initializes the Authenticator with a cookie manager and Firestore client.

        Args:
            cookies: A cookie manager instance for managing user sessions.
        """
        self.oauth_client_id = get_secret(GCP_PROJECT, OAUTH_CLIENT_ID_SECRETMANAGER)
        self.oauth_client_secret = get_secret(
            GCP_PROJECT, OAUTH_CLIENT_SECRET_SECRETMANAGER
        )
        self.cookies = cookies
        self.db = self._get_firestore_client()
        self.oauth2 = self._init_oauth_component()
        self._init_session_state()



    @staticmethod
    @st.cache_resource(show_spinner=False)
    def _get_firestore_client():
        """
        Initializes a Firestore client using Application Default Credentials (ADC).
        """
        try:
            return firestore.Client(project=GCP_PROJECT, database=FIRESTORE_DATABASE)
        except Exception as e:
            st.error(
                f"🔥 Could not connect to Firestore. Ensure GCP_PROJECT is set and you are authenticated. Error: {e}"
            )
            st.stop()

    def _init_oauth_component(self):
        """
        Initializes the OAuth2 component with credentials.

        Returns:
            OAuth2Component: An instance of the OAuth2 component.
        """
        return OAuth2Component(
            client_id=self.oauth_client_id,
            client_secret=self.oauth_client_secret,
            authorize_endpoint=AUTHORIZE_ENDPOINT,
            token_endpoint=TOKEN_ENDPOINT,
            revoke_token_endpoint=REVOKE_ENDPOINT,
        )

    @staticmethod
    def _init_session_state():
        """
        Initializes required keys in Streamlit's session state.
        """
        for key in ["auth_token_info", "user_email", "creds"]:
            if key not in st.session_state:
                st.session_state[key] = None

    def _save_token_to_firestore(self, user_email, token):
        """
        Saves a user's token to a Firestore document.

        Args:
            user_email (str): The email of the user, used as the document ID.
            token (dict): The OAuth token dictionary to save.
        """
        try:
            token_with_ts = token.copy()
            token_with_ts["last_updated"] = firestore.SERVER_TIMESTAMP
            doc_ref = self.db.collection(FIRESTORE_TOKEN_COLLECTION).document(
                user_email
            )
            doc_ref.set(token_with_ts)
        except GoogleAPICallError as e:
            st.error(f"🔥 Firestore Error: Failed to save token. {e}")

    def _load_token_from_firestore(self, user_email):
        """
        Loads a token from a Firestore document.

        Args:
            user_email (str): The email of the user to load the token for.

        Returns:
            dict | None: The token dictionary, or None if not found or an error occurs.
        """
        try:
            doc_ref = self.db.collection(FIRESTORE_TOKEN_COLLECTION).document(
                user_email
            )
            doc = doc_ref.get()
            return doc.to_dict() if doc.exists else None
        except GoogleAPICallError as e:
            st.error(f"🔥 Firestore Error: Failed to load token. {e}")
            return None

    def _clear_token_from_firestore(self, user_email):
        """
        Deletes a user's token document from Firestore.

        Args:
            user_email (str): The email of the user whose token to delete.
        """
        try:
            self.db.collection(FIRESTORE_TOKEN_COLLECTION).document(user_email).delete()
        except GoogleAPICallError as e:
            st.error(f"🔥 Firestore Error: Failed to clear token. {e}")

    @staticmethod
    def _extract_user_email(token_info):
        """
        Extracts the user's email from the token info dictionary.

        Args:
            token_info (dict): The OAuth token info.

        Returns:
            str | None: The user's email, or None if it cannot be found.
        """
        if not token_info:
            return None
        if "id_token_claims" in token_info and "email" in token_info["id_token_claims"]:
            return token_info["id_token_claims"]["email"]
        if "id_token" in token_info:
            try:
                id_token = token_info["id_token"]
                payload = id_token.split(".")[1]
                payload += "=" * ((4 - len(payload) % 4) % 4)
                decoded_data = json.loads(base64.urlsafe_b64decode(payload))
                return decoded_data.get("email")
            except Exception:
                return None
        return None

    def _create_credentials_object(self, token_info):
        """
        Creates a google.oauth2.credentials.Credentials object from token info.

        Args:
            token_info (dict): The OAuth token info.

        Returns:
            Credentials: A Google credentials object.
        """
        scopes = []
        if token_info.get("scopes"):
            scopes = list(token_info["scopes"])
        elif token_info.get("scope"):
            scopes = token_info["scope"].split()

        if not scopes:
            scopes = OAUTH_SCOPES

        return Credentials(
            token=token_info.get("access_token"),
            refresh_token=token_info.get("refresh_token"),
            id_token=token_info.get("id_token"),
            token_uri=TOKEN_ENDPOINT,
            client_id=self.oauth_client_id,
            client_secret=self.oauth_client_secret,
            scopes=scopes,
        )

    def check_session(self):
        """
        Checks for an existing session and restores it from a cookie and Firestore token.
        Also validates that the current token has all required scopes.
        """
        if st.session_state.get("user_email") and st.session_state.get("auth_token_info"):
            # Verify scopes
            token_info = st.session_state.get("auth_token_info")
            token_scopes = set(token_info.get("scopes", []))
            required_scopes = set(OAUTH_SCOPES)
            
            # Allow for some flexibility if OAUTH_SCOPES has specific versions, but generally we want exact match or superset
            # For simplicity, we check if required_scopes is a subset of token_scopes
            if not required_scopes.issubset(token_scopes):
                st.warning("⚠️ New permissions are required. Please log in again.")
                self.logout_widget(key="invalid_scopes_logout")
                st.stop()
                return

            return

        user_email_from_cookie = self.cookies.get("user_email")
        if user_email_from_cookie:
            token = self._load_token_from_firestore(user_email_from_cookie)
            if token:
                # Check scopes before restoring
                token_scopes = set(token.get("scopes", []))
                required_scopes = set(OAUTH_SCOPES)
                
                if required_scopes.issubset(token_scopes):
                    st.session_state.auth_token_info = token
                    st.session_state.user_email = user_email_from_cookie
                    st.session_state.creds = self._create_credentials_object(token)
                else:
                    self.cookies["user_email"] = "" # Clear invalid cookie
            else:
                self.cookies["user_email"] = ""

    def login_widget(self):
        """
        Displays the login button and handles the OAuth authentication flow.
        """

        _, col2, _ = st.columns([1, 1, 1])
        with col2:
            st.info("Please log in to continue.")
            extras: Dict[str, str] = {
                "access_type": "offline",
                "include_granted_scopes": "true",
                "hd": ALLOWED_DOMAIN,
            }
            current_user = st.session_state.get("user_email") or self.cookies.get("user_email")
            tok = self._load_token_from_firestore(current_user) if current_user else None

            required_scopes = set(OAUTH_SCOPES)
            token_scopes = set((tok or {}).get("scopes", []))
            if (
                (not tok)
                or (not tok.get("refresh_token"))
                or (not required_scopes.issubset(token_scopes))
            ):
                extras["prompt"] = "consent"

            result = self.oauth2.authorize_button(
                name="Login with Google",
                redirect_uri=REDIRECT_URI,
                scope=" ".join(OAUTH_SCOPES),
                extras_params=extras,
                pkce="S256",
            )

        if result and "token" in result:                          # OAuth returned a token
            token_info = result["token"]
            user_email = self._extract_user_email(token_info)

            if not user_email:
                st.error("❌ Failed to extract user email from OAuth token.")
                return

            if not user_email.endswith(f"@{ALLOWED_DOMAIN}"):    # Domain check
                st.error(f"❌ Access restricted to @{ALLOWED_DOMAIN} accounts.")
                self.oauth2.revoke_token(token_info.get("access_token"))
                st.stop()
                return

            scope_str = token_info.get("scope", "")              # All good — save session
            token_info["scope"] = scope_str
            token_info["scopes"] = (
                scope_str.split()
                if isinstance(scope_str, str)
                else (token_info.get("scopes") or [])
            )
            self._save_token_to_firestore(user_email, token_info)
            self.cookies["user_email"] = user_email
            self.cookies.save()
            st.session_state.auth_token_info = token_info
            st.session_state.user_email = user_email
            st.session_state.creds = self._create_credentials_object(token_info)
            st.rerun()

        elif result:
            st.error(f"OAuth Error: {result}")


    def logout_widget(self, key="default_logout_button"):
        """
        Displays the logout button and handles session termination.
        """
        if st.button("Logout", key=key):
            user_email = st.session_state.get("user_email")
            if user_email:
                self._clear_token_from_firestore(user_email)
                self.cookies["user_email"] = ""
                self.cookies.save()
            for key in ["user_email", "auth_token_info", "creds"]:
                if key in st.session_state:
                    del st.session_state[key]

            st.rerun()

    def get_user_name(self):
        """
        Returns the user's name from the token.

        Returns:
            str | None: The user's name, or their email as a fallback, or None.
        """
        token_info = st.session_state.get("auth_token_info")
        if token_info:
            if "id_token_claims" in token_info:
                return token_info["id_token_claims"].get(
                    "name", st.session_state.get("user_email")
                )
            elif "id_token" in token_info:
                try:
                    id_token = token_info["id_token"]
                    payload = id_token.split(".")[1]
                    payload += "=" * ((4 - len(payload) % 4) % 4)
                    decoded_data = json.loads(base64.urlsafe_b64decode(payload))
                    return decoded_data.get("name")
                except Exception:
                    return st.session_state.get("user_email")
        return None

    def get_refreshed_credentials(self):
        """
        Checks if credentials have expired and attempts to refresh them.

        Returns:
            Credentials | None: The valid (potentially refreshed) credentials object, or None if refresh fails.
        """
        creds = st.session_state.get("creds")
        if not creds:
            return None

        if creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
                st.session_state["creds"] = creds

                token_info = {
                    "access_token": creds.token,
                    "refresh_token": creds.refresh_token,
                    "token_uri": creds.token_uri,
                    "client_id": creds.client_id,
                    "client_secret": creds.client_secret,
                    "scopes": list(creds.scopes or []),
                    "scope": " ".join(creds.scopes or []),
                    "id_token": creds.id_token,
                }
                user_email = st.session_state.get("user_email")
                if user_email:
                    self._save_token_to_firestore(user_email, token_info)

            except Exception as e:
                st.warning(
                    f"Your session has likely expired. Please log in again. (Error: {e})"
                )
                self.logout_widget()
                return None

        return creds
