/** Paste into a ServiceNow BYOG request transformer with ECMAScript 2021 enabled. */
export const SERVICENOW_GUARDIAN_REQUEST = String.raw`(function(inputs) {
  function contentOf(value) {
    if (typeof value === 'string') return value;
    if (value === null || typeof value === 'number' || typeof value === 'boolean') return String(value);
    if (Array.isArray(value)) return value.map(contentOf).join('\n');
    if (typeof value === 'object') return Object.keys(value).map(function(key) {
      return key + ': ' + contentOf(value[key]);
    }).join('\n');
    throw new Error('Signet Guardian: unsupported prompt value; inspect the Guardian input schema');
  }
  const prompt = typeof inputs === 'string' ? inputs : inputs && inputs.prompt;
  if (prompt === undefined || prompt === null) {
    throw new Error('Signet Guardian: expected a text input or inputs.prompt');
  }
  const content = contentOf(prompt);
  if (!content.trim()) throw new Error('Signet Guardian: prompt contains no text');
  return { body: { content: content }, headers: { 'Content-Type': 'application/json' } };
})(inputs);`;

/** Converts the native Signet verdict into ServiceNow's documented All-guardrails response. */
export const SERVICENOW_GUARDIAN_RESPONSE = String.raw`(function(inputs) {
  function decoded(value) {
    if (typeof value !== 'string') return value;
    try { return JSON.parse(value); }
    catch (error) { throw new Error('Signet Guardian: response is not valid JSON; check the Guardian HTTP connection response'); }
  }
  const envelope = decoded(inputs);
  const body = decoded(envelope && envelope.response_body);
  if (!body || typeof body !== 'object' || !body.security || !body.safety) {
    throw new Error('Signet Guardian: missing safety/security verdict; check endpoint, credentials and HTTP response');
  }
  function checked(value) {
    if (typeof value.flagged !== 'boolean' || !Array.isArray(value.categories) ||
        !value.categories.every(function(category) { return typeof category === 'string'; })) {
      throw new Error('Signet Guardian: invalid flagged/categories response; evaluation cannot be trusted');
    }
    return { flagged: value.flagged, categories: value.categories.slice() };
  }
  return { security: checked(body.security), safety: checked(body.safety) };
})(inputs);`;
