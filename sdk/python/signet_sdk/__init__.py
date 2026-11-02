"""Signet SDK: route an agent's model and tool calls through the Signet gateway.

    from signet_sdk import SignetAgent
    agent = SignetAgent.from_env()
    client = agent.openai_client()

Configuration (environment): SIGNET_GATEWAY_URL, SIGNET_CONTROL_URL and either
SIGNET_BOOTSTRAP_CREDENTIAL / SIGNET_BOOTSTRAP_FILE (self-hosted) or SIGNET_CLIENT_ID and
SIGNET_CLIENT_SECRET (vendor platforms). The agent needs no model or tool credentials of its own.
"""

__version__ = "0.1.0"

from .agent import SignetAgent, raise_for_gateway  # noqa: E402
from .config import SignetConfig  # noqa: E402
from .errors import SignetAuthError, SignetConfigError, SignetError, SignetPolicyError, SignetUnavailable, SignetUpstreamError  # noqa: E402
from .identity import SignetAuth, TokenManager, decode_claims  # noqa: E402

__all__ = [
    "SignetAgent",
    "SignetConfig",
    "SignetAuth",
    "TokenManager",
    "decode_claims",
    "raise_for_gateway",
    "SignetError",
    "SignetConfigError",
    "SignetAuthError",
    "SignetPolicyError",
    "SignetUnavailable",
    "SignetUpstreamError",
]
