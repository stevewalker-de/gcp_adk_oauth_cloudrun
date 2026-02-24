from typing import Optional

from google.adk import Agent
from google.adk.models import Gemini
from google.genai import Client, types

from config import GCP_PROJECT, LOCATION, MODEL_NAME


class ConfiguredGemini(Gemini):
    """
    A subclass of Gemini that allows configuring project, location, and credentials.
    This is necessary because the standard ADK Gemini class relies on default environment/client settings.
    """

    def __init__(self, project: str, location: str, credentials=None, **kwargs):
        super().__init__(**kwargs)
        self._project = project
        self._location = location
        self._credentials = credentials
        self._cached_client = None

    @property
    def api_client(self) -> Client:
        if self._cached_client is None:
            self._cached_client = Client(
                vertexai=True,
                project=self._project,
                location=self._location,
                credentials=self._credentials,
                http_options=types.HttpOptions(
                    headers=self._tracking_headers(),
                    retry_options=self.retry_options,
                    base_url=self.base_url,
                ),
            )
        return self._cached_client


def create_joke_agent(
    credentials,
    project: str = GCP_PROJECT,
    location: str = LOCATION,
    model_name: str = MODEL_NAME,
) -> Agent:
    """
    Creates and returns a compliant ADK Agent configured for telling jokes.
    """
    model = ConfiguredGemini(
        model=model_name, project=project, location=location, credentials=credentials
    )

    agent = Agent(
        model=model,
        name="joke_agent",
        instruction=(
            "You are a friendly agent who loves telling knock-knock jokes. "
            "When the user says 'tell me a joke', you start a knock-knock joke. "
            "You must wait for the user to say 'who's there?' before continuing. "
            "Keep it fun and lighthearted, and related to cloud computing or Google"
        ),
    )
    return agent


def generate_reply(agent: Agent, user_input: str, history: list = None) -> str:
    """
    Generates a reply from the agent using its configured model.
    Since basic ADK Agent doesn't expose a simple synchronous 'chat' method equivalent to
    generate_content with history for this use case, we manually invoke the model
    while respecting the agent's configuration.
    """
    # Construct contents from history
    contents = []
    if history:
        for message in history:
            role = message.get("role")
            if role == "assistant":
                role = "model"
            text = message.get("content", "")
            contents.append({"role": role, "parts": [{"text": text}]})

    contents.append({"role": "user", "parts": [{"text": user_input}]})

    try:
        model_instance = agent.model
        if not isinstance(model_instance, ConfiguredGemini):
            raise ValueError("Agent model is not ConfiguredGemini")

        response = model_instance.api_client.models.generate_content(
            model=model_instance.model,
            contents=contents,
            config={"system_instruction": agent.instruction},
        )
        return response.text
    except Exception as e:
        return f"Error communicating with agent: {e}"


if __name__ == "__main__":
    print("Agent initialized. Type 'quit' to exit.")
    from google.auth import default

    creds, _ = default()

    agent = create_joke_agent(creds)
    history = []
    while True:
        user_input = input("You: ")
        if user_input.lower() in ["quit", "exit"]:
            break
        reply = generate_reply(agent, user_input, history)
        print(f"Agent: {reply}")
        history.append({"role": "user", "content": user_input})
        history.append({"role": "assistant", "content": reply})
