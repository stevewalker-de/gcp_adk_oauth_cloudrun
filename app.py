import streamlit as st

from auth import Authenticator
from cookie_manager import get_cookie_manager
from simple_joke_agent import create_joke_agent, generate_reply
from config import GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET

# --- APP SETUP ---
st.set_page_config(page_title="Simple OAuth Test", page_icon="🔐")


# --- UI LOGIC ---
cookies = get_cookie_manager()
if not cookies.ready():
    st.stop()

authenticator = Authenticator(cookies)
authenticator.check_session()
if st.session_state.get("user_email"):
    with st.sidebar:
        st.header("🔐 Auth Details")
        st.success(f"Logged in as:\n**{st.session_state.user_email}**")

        # Display Token Info for Debugging
        with st.expander("Show Token Info"):
            st.json(st.session_state.get("auth_token_info"))

        # Logout Button
        st.write("---")
        authenticator.logout_widget()

    # --- JOKE AGENT INTEGRATION ---
    st.title("🤖 Knock-Knock Agent")
    st.write("Ask me to tell you a joke!")

    # Initialize Joke Agent if not already in session
    if "agent" not in st.session_state:
        try:
            # Use creds from auth if available
            creds = None
            if st.session_state.get("creds"):
                creds = authenticator.get_refreshed_credentials()

            # Create the agent using the factory function
            st.session_state.agent = create_joke_agent(credentials=creds)
            st.session_state.messages = []

        except Exception as e:
            st.error(f"Failed to initialize agent: {e}")

    # Display chat messages from history on app rerun
    if "messages" not in st.session_state:
        st.session_state.messages = []

    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    # React to user input
    if prompt := st.chat_input("tell me a joke"):
        # Display user message in chat message container
        with st.chat_message("user"):
            st.markdown(prompt)
        # Add user message to chat history
        st.session_state.messages.append({"role": "user", "content": prompt})

        # Display assistant response in chat message container
        with st.chat_message("assistant"):
            message_placeholder = st.empty()
            full_response = ""
            with st.spinner("Thinking..."):
                try:
                    # Use the generate_reply helper function
                    full_response = generate_reply(
                        st.session_state.agent, prompt, st.session_state.messages[:-1]
                    )
                    message_placeholder.markdown(full_response)
                except Exception as e:
                    full_response = f"Error: {e}"
                    message_placeholder.markdown(full_response)

            # Add assistant response to chat history
            st.session_state.messages.append(
                {"role": "assistant", "content": full_response}
            )

else:
    st.info("👋 You are not logged in.")
    st.write("Click the button below to start the OAuth flow.")

    # Login Button
    authenticator.login_widget()
