// The onboarding guide's content, kept apart from its panel so wording can change without touching UI.
// It must stay true for every agent: describe what Signet does, never one provider's API.

export interface GuideBlock { heading?: string; text?: string; steps?: string[]; points?: string[]; table?: [string, string][]; code?: string }
export interface GuideTopic { id: string; group: string; title: string; summary: string; keywords?: string; blocks: GuideBlock[] }

export const GUIDE_TOPICS: GuideTopic[] = [
  {
    id: 'choose', group: 'Start here', title: 'Which way should I add my agent?', summary: 'Pick the route that matches what you have.', keywords: 'start begin route option',
    blocks: [{
      table: [
        ['I know the agent, and I built or bought it', 'Add one agent I know about'],
        ["I don't know which agents my company has", 'Find the agents my company already has'],
        ['One service runs many agents, and it has an API', 'Connect a platform that runs many agents'],
        ['My agent only calls a model and uses no other apps', 'Quick connect'],
      ],
    }, { text: 'Not sure? Use "Add one agent I know about". It asks in plain language and covers every connection method.' }],
  },
  {
    id: 'before', group: 'Start here', title: 'What to keep ready', summary: 'A short list that avoids most delays.', keywords: 'prepare need checklist',
    blocks: [{
      points: [
        'The agent\'s name, what it does, and who it is for.',
        'Who it affects, what information it can see, and whether its mistakes can be undone.',
        'Which apps it uses and what it does in each one.',
        'For a platform connection: its API address, API key and API documentation.',
        'For a cloud account: an access key or token allowed to read that account.',
        'The people who must approve it. Higher-risk agents need Security, Risk or the governance board.',
      ],
    }],
  },
  {
    id: 'steps', group: 'Start here', title: 'The six steps', summary: 'What happens at each step, and who does it.', keywords: 'about people data what it can do safety check approval connect tier risk seal shadow',
    blocks: [
      { heading: '1. About', text: 'Name the agent, say what it does, and say who runs it. A vendor-hosted agent also needs the vendor\'s name.' },
      { heading: '2. People & data', text: 'Say who it affects, what it can see, whether it decides things about people, and whether its mistakes can be undone. These answers set its risk level.' },
      { heading: '3. What it can do', text: 'List its actions and choose how much freedom it has. Anything not listed is blocked. You can continue without apps and add them before approval, except a vendor-hosted agent, which needs at least one.' },
      { heading: '4. Safety check', text: 'Signet shows the risk level. Depending on that level you answer safety questions, complete reviews and run tests. "No" does not fail the agent; it becomes a to-do. Serious to-dos must be closed before it can move on.' },
      { heading: '5. Approval', text: 'The required people sign, and each is notified. Their signatures produce the agent\'s seal, its permission to run.' },
      { heading: '6. Connect', text: 'Give your agent its connection details and send a test. It starts in shadow mode, which records would-blocks without stopping normal requests. Review the results, then move it to enforce.' },
      { heading: 'Risk levels', table: [['Low (T4)', 'Automatic check, no signature'], ['Moderate (T3)', 'Short safety check; you and Security approve'], ['High (T2)', 'Risk team confirms the rating, deeper reviews, test results; Owner, Security and Risk approve'], ['Critical (T1)', 'As High, and the governance board also approves']] },
      { text: 'You can leave at any point. Open the agent from the Agents list and Signet returns you to the step it needs next.' },
    ],
  },
  {
    id: 'one', group: 'Ways to add', title: 'Add one agent', summary: 'The guided route, for any agent you know about.', keywords: 'self hosted framework no code vendor third party langchain n8n copilot agentforce oauth bootstrap hybrid',
    blocks: [
      { steps: ['Choose "Add one agent I know about".', 'Fill in the three forms: About, People & data, What it can do.', 'Open "Connection method" on the third form if you need to change it.', 'Select "See the risk result", then follow the steps Signet shows.'] },
      { heading: 'Which connection method?', table: [
        ['REST API', 'The agent has an API that Signet can read to see and monitor it.'],
        ['OAuth 2.0', 'Uses a Client ID and Client Secret. Suits platforms and long-running agents.'],
        ['Bootstrap / Workload JWT', 'Your own code exchanges a one-time credential for short-lived identity. Works with the Python SDK.'],
        ['Private network / On-prem', 'The agent or its tools are not on the public internet. A connector runner connects outbound.'],
      ] },
      { text: 'Vendor-hosted agents can only use OAuth 2.0 or REST API.' },
    ],
  },
  {
    id: 'quick', group: 'Ways to add', title: 'Quick connect', summary: 'One form to a working key, for model-only agents.', keywords: 'key base url gateway test request',
    blocks: [
      { steps: ['Answer the short form about the agent.', 'If Signet asks more questions, answer them honestly.', 'Copy the API key. It is shown only once.', 'In your agent, set the base URL and API key to the values shown.', 'Select "Send test request".'] },
      { text: 'A high or critical answer sends the agent to the full review, and no key is issued until that is done. Lower gaps are recorded for you to close later.' },
    ],
  },
  {
    id: 'find', group: 'Ways to add', title: 'Find agents in a cloud or AI account', summary: 'Scan an account and choose what to bring in.', keywords: 'vercel aws azure google cloud gcp copilot studio openai anthropic scan discover token admin key service account',
    blocks: [
      { steps: ['Choose the platform and enter its details.', 'Select Connect. Signet checks the details and scans the account.', 'Review what it found.', 'Select "Connect to Signet" on each agent you want to bring in.'] },
      { heading: 'What each platform asks for', table: [
        ['Vercel', 'Access token; Team ID if needed'],
        ['AWS', 'Access key ID and secret access key; regions if needed'],
        ['Azure', 'Tenant ID, App (client) ID, client secret, subscription ID'],
        ['Google Cloud', 'Service account key (JSON); regions if needed'],
        ['Copilot Studio', 'Environment URL, Tenant ID, App (client) ID, client secret'],
        ['OpenAI, Anthropic', 'Organization admin key'],
      ] },
      { text: 'Finding an agent does not approve it. Each one still goes through the steps for its risk level.' },
    ],
  },
  {
    id: 'platform', group: 'Ways to add', title: 'Connect a platform through its API', summary: 'Tell Signet how to read any REST API.', keywords: 'rest api base url endpoint mapping adapter json pointer items discover test track executions pagination x-api-key',
    blocks: [
      { steps: ['Enter the API\'s base URL and key.', 'Open "API settings and endpoint mapping" and fill in the paths from the provider\'s API documentation.', 'Select "Save connection / mappings", then "Test connection & find agents".', 'Choose the agents to bring in.', 'On each agent\'s page, select "Sync provider activity" to check its history is arriving.'] },
      { heading: 'Base URL and paths', text: 'Signet adds each path to the end of the base URL. If the base URL ends in /api/v1, write /agents and not /api/v1/agents. The address must use HTTPS on port 443; private addresses need an enrolled runner.' },
      { heading: 'Pick the right test path', text: 'Use a harmless GET that really exists and requires the key, usually the agent list. A public health page can pass the test, but authentication then stays unverified and remote actions stay blocked. Avoid "/" unless the API really answers there.' },
      { heading: 'Copy paths exactly', text: 'Use {id} where the agent ID goes. Remove any marks from the documentation, such as a trailing *, because Signet sends them as written.' },
      { heading: 'See the real response first', text: 'Mapping is easiest when you can see what the API returns. Ask your provider for a sample, or run this in a terminal (on Windows PowerShell, type curl.exe). Replace the header name, key and address with your own.', code: 'curl -H "x-api-key: YOUR_KEY" https://your-api.example.com/api/v1/agents' },
      { heading: 'Set "items": where the list is', table: [
        ['[ {...}, {...} ]', 'leave empty'],
        ['{ "agents": [ ... ] }', '/agents'],
        ['{ "data": [ ... ] }', '/data'],
        ['{ "data": { "agents": [ ... ] } }', '/data/agents'],
      ] },
      { heading: 'Set the other fields: inside one record', text: 'id, name, status and timestamp are read from a single record, not the whole response. If a record is { "agentId": "a1", "title": "Helper" }, then id is /agentId and name is /title. Names are case-sensitive.' },
      { points: ['Agents and executions have separate mappings, and their responses often differ. Check both.', 'Leave optional fields empty if some records may hold null, because a record with a null mapped field is rejected.', 'If the response includes total, offset and limit, turn on pagination to get every page. Otherwise only the first page arrives.'] },
    ],
  },
  {
    id: 'connect', group: 'Ways to add', title: 'Connect your agent after approval', summary: 'What to do at the Connect step.', keywords: 'credentials not provisioned client secret bootstrap environment variables python docker sidecar shadow enforce',
    blocks: [
      { table: [
        ['REST API', 'Signet reads the agent\'s API. It reports provider activity, but does not intercept the agent\'s internal model or tool calls.'],
        ['OAuth 2.0', 'Create a Client ID and Secret on the Connection tab and add them to the agent or vendor platform.'],
        ['Bootstrap', 'Generate the one-time credential and set the values shown where the agent runs.'],
        ['Private network', 'Enroll a connector runner on your network, then register the private tool on it.'],
      ] },
      { text: 'Secrets are shown once, so copy them straight away. Python, Docker, n8n and sidecar setups are on the agent\'s Connection tab.' },
      { heading: 'Real-time control: send calls through Signet', text: 'Signet can only block calls that pass through its gateway. A REST connection alone only reports activity.' },
      { steps: ['On "What it can do", choose or add the agent\'s own LLM. Its key goes to the Secrets Broker.', 'After approval, create an API key at the Connect step.', 'Where the agent runs, set its model address to the Signet address shown, and its API key to the Signet key.', 'Send a test. Remove the LLM key from the agent so it cannot go around Signet.'] },
      { heading: 'Tools that run inside the agent', text: 'No code change is needed. When the agent uses its own LLM, Signet checks each tool call the LLM proposes. A call the seal does not allow never reaches the agent, so it never runs, and the agent receives a normal reply giving the reason. List those tools under "Tools inside the agent" on "What it can do", because anything not listed is blocked. Signet cannot see a tool the agent runs without its LLM asking.' },
      { table: [['Agents using an OpenAI-style client', 'Use the Signet address ending in /v1'], ['Agents using Ollama\'s own API', 'Use the same address without /v1']] },
    ],
  },
  {
    id: 'errors', group: 'Fix a problem', title: 'Connection errors', summary: 'Look up the code shown in the red box.', keywords: 'error red EXTERNAL_NOT_FOUND EXTERNAL_AUTH VALIDATION EXTERNAL_CONTENT EXTERNAL_SCHEMA EXTERNAL_REDIRECT EXTERNAL_TIMEOUT EXTERNAL_RATE_LIMIT EXTERNAL_DNS EXTERNAL_TLS EXTERNAL_NETWORK EXTERNAL_HTTP EXTERNAL_DESTINATION EXTERNAL_CONFIG EXTERNAL_SIZE SYNC_TIMEOUT REMOTE_CONNECTION 404 401 403 429 mapped list 1000 records',
    blocks: [
      { heading: 'EXTERNAL_NOT_FOUND (HTTP 404)', text: 'A path does not exist on that API. Check the test path first, because it runs first. Compare it with the documentation, and make sure the base URL\'s prefix is not repeated in the path.' },
      { heading: 'EXTERNAL_AUTH (HTTP 401 or 403)', text: 'The API refused the key. Check the key, its permissions, the authentication type and the header name. Header names differ between providers.' },
      { heading: 'VALIDATION: "Mapped list must contain at most 1000 records"', text: 'This usually does not mean you have too many records. The same message appears when "items" does not point to a list. Compare the real response with the "items" table in "Connect a platform through its API". If it appears after agents were found, check the execution mapping. If there really are over 1000 records, narrow the scope at the provider, because Signet reads at most 1000.' },
      { heading: 'VALIDATION: "None of the records matched the mapping"', text: 'The list was found, but id or another field did not match. Check those paths against one record, including capital letters.' },
      { heading: 'VALIDATION: "Mapped id must be a non-empty string", or similar', text: 'That field is missing, null, or the wrong type in a record. Point it to another field, or leave it empty if it is optional.' },
      { heading: 'VALIDATION: "Mapped timestamp must be an ISO date"', text: 'The timestamp field holds something that is not a date. Point it to a real date field, or leave it empty.' },
      { heading: 'EXTERNAL_CONTENT', text: 'The address answered with something other than JSON, usually a web page. The base URL probably points to the website and not its API.' },
      { heading: 'EXTERNAL_SCHEMA', text: 'The response could not be read as expected. Check that the path returns valid JSON.' },
      { heading: 'EXTERNAL_REDIRECT', text: 'The API redirected the request. Use the final address, often a version with or without www or a trailing slash.' },
      { heading: 'EXTERNAL_TIMEOUT', text: 'The API was too slow. Raise the request timeout (up to 30000 milliseconds), or check whether the service is sleeping or down.' },
      { heading: 'EXTERNAL_RATE_LIMIT (HTTP 429)', text: 'The provider is limiting requests. Wait and retry, or raise the sync interval.' },
      { heading: 'EXTERNAL_DNS, EXTERNAL_TLS, EXTERNAL_NETWORK', text: 'Signet could not reach the address. Check the spelling, that the certificate is valid, and that the service is online.' },
      { heading: 'EXTERNAL_DESTINATION', text: 'The address is not allowed. It must be public HTTPS on port 443, with no credentials in the URL. Private addresses need a connector runner. An administrator\'s allowlist can also block a host.' },
      { heading: 'EXTERNAL_HTTP', text: 'The API returned another error, such as a 500. The provider\'s own logs will explain it, since Signet hides the response in case it contains credentials.' },
      { heading: 'SYNC_TIMEOUT', text: 'Reading all the pages took too long. Narrow the scope at the provider, then retry.' },
      { heading: 'REMOTE_CONNECTION', text: 'Remote actions need a verified test and enforced credentials. Use a test path that requires the key, then test again.' },
    ],
  },
  {
    id: 'status', group: 'Fix a problem', title: 'Stuck or unexpected status', summary: 'Badges and waiting states explained.', keywords: 'credentials not provisioned not connected pending approval no activity zero gateway needs attention waiting confirm rejected risk team held hold',
    blocks: [
      { heading: 'Credentials not provisioned', text: 'It is approved, but no credential has been issued for it to call Signet\'s gateway. Create one on the Connection tab if the agent will use the gateway. This does not stop REST monitoring, which uses the provider\'s API key.' },
      { heading: 'Not connected', text: 'Signet has not verified a call with a current identity, or the identity can no longer be renewed. Send a test using the current connection details. A verified connection with renewable credentials stays Connected (idle) when there is no recent traffic.' },
      { heading: 'Activity shows 0', text: 'Look for a red error above the numbers first, since a failed sync also leaves them at 0. Select "Sync provider activity" after fixing it. The chart covers only the last 24 hours, so older activity will not appear there.' },
      { heading: '"Your risk team has been asked to confirm"', text: 'High and critical ratings must be confirmed by a risk officer or the governance board. You can only wait or contact them. The page moves on once they confirm.' },
      { heading: 'Waiting for approval', text: 'Each required person has been notified. They decide in Needs you. Contact whoever has not signed.' },
      { heading: 'High-risk requests held for approval', text: 'If a safety detector is unavailable, requests from high and critical agents are held for a person to decide. This is intended safety behaviour, not a setup fault.' },
      { heading: 'Not approved', text: 'The agent cannot run. The reasons are on its record.' },
    ],
  },
  {
    id: 'words', group: 'Fix a problem', title: 'Words used in Signet', summary: 'Quick meanings.', keywords: 'glossary meaning seal shadow enforce quarantine manifest gateway ledger tier runner',
    blocks: [{
      table: [
        ['Seal', 'The signed approval that lets an agent run, within limits and until a set date.'],
        ['Shadow', 'Signet records what it would block without stopping normal requests.'],
        ['Enforce', 'Signet actually blocks what its policies do not allow.'],
        ['Quarantine', 'The agent is stopped until someone reviews it.'],
        ['Gateway', 'The checkpoint that an agent\'s governed model and tool calls pass through.'],
        ['Runner', 'A small connector on your network that lets Signet reach private systems.'],
        ['Mapping', 'Instructions that tell Signet where each value sits in an API\'s response.'],
      ],
    }],
  },
];

/** Opens on the topic that matches the page the person is stuck on. */
export function guideTopicFor(pathname: string): string {
  if (pathname.endsWith('/new/platform')) return 'platform';
  if (pathname.endsWith('/new/find')) return 'find';
  if (pathname.endsWith('/new/one')) return 'one';
  if (pathname.endsWith('/quick')) return 'quick';
  if (pathname.endsWith('/setup')) return 'steps';
  if (pathname.endsWith('/new')) return 'choose';
  return 'status';
}

const blockText = (b: GuideBlock) => [b.heading, b.text, b.code, ...(b.steps ?? []), ...(b.points ?? []), ...(b.table ?? []).flat()].filter(Boolean).join(' ');

export function searchGuide(query: string): GuideTopic[] {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (!words.length) return GUIDE_TOPICS;
  return GUIDE_TOPICS.filter((t) => { const all = [t.title, t.summary, t.keywords, ...t.blocks.map(blockText)].join(' ').toLowerCase(); return words.every((w) => all.includes(w)); });
}
