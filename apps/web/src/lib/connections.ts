import type { ConnectionMethod } from '@signet/core/types';

export const CONNECTION_METHODS: { id: ConnectionMethod; label: string; description: string }[] = [
  { id: 'oauth', label: 'OAuth 2.0', description: 'Use a Client ID and Client Secret. Recommended for platforms and long-running agents.' },
  { id: 'rest', label: 'REST API', description: 'No SDK required. Generate credentials, get a Bearer token, then call the API using cURL, Postman or any language.' },
  { id: 'bootstrap', label: 'Bootstrap / Workload JWT', description: 'Exchange a one-time credential for a short-lived identity. Works with the Python SDK.' },
  { id: 'hybrid', label: 'Private network / On-prem', description: 'Connect local agents outbound and reach private REST tools through a connector runner.' },
];

