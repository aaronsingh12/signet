/** Authentication refusals do not establish a working gateway connection. */
export const GATEWAY_AUTH_ERRORS: readonly string[] = ['invalid_token', 'token_expired', 'token_revoked', 'no_active_seal', 'agent_killed', 'agent_quarantined', 'seal_mismatch', 'seal_expired', 'wrong_environment', 'invalid_api_key'];
