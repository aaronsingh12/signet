# ServiceNow AI Agent ko Signet se connect karna

Setup reference: 17 November 2026. Ye guide is project ke implemented UI aur observed ServiceNow setup par based hai. ServiceNow release, roles aur application scope ke hisaab se screens alag ho sakti hain.

## 1. Abhi kya working hai aur kya pending hai

| Part | Verified state |
| --- | --- |
| Public ngrok address | Local Signet web server ko expose karta hai; latest restart ke baad `/healthz` ne HTTP 200 JSON diya |
| Signet → ServiceNow OAuth | Authorization complete hua; MCP discovery working |
| MCP tools | Do tools discover hue: reliability status aur topology |
| Existing Perimetra Agent | Signet registry mein linked; approval complete |
| Gateway route | `servicenow-cmdb` alias prepared; do read actions approved |
| Signet workload credentials | UI se create, encrypted persistence aur refresh ke baad retrieval implemented |
| ServiceNow outbound connection | OAuth provider, profile, credential, HTTP connection aur MCP server record saved |
| ServiceNow Control Tower registration | Pending investigation: Signet gateway inventory/CI record nahi mil raha |
| Real governed agent traffic | Latest screenshot mein zero requests; agent **Not connected / Linked** hai |
| Agent execution monitoring | Configured aur verified hone ka evidence nahi; MCP discovery execution history nahi deta |

**Setup complete ya agent fully governed abhi claim nahi karna.** Approval, credentials aur tool discovery actual gateway traffic ka substitute nahi hain.

## 2. Do alag OAuth connections samjho

```text
Signet console -- ServiceNow-issued OAuth --> ServiceNow MCP server
    Tool metadata discover karna aur upstream tools access karna

ServiceNow AI agent -- Signet-issued OAuth --> Signet MCP gateway
    Policy checks / evidence --> ServiceNow MCP server
```

Pehle connection ka Client ID/Secret ServiceNow issue karta hai. Doosre ka Signet issue karta hai (`scl_...` / `scs_...`). Inko interchange mat karo.

Existing agent ke native tools jo Signet route bypass karte hain unki calls automatically intercepted nahi hoti. Sirf Signet se routed calls par gateway controls apply hote hain. ServiceNow ke internal model calls bhi is MCP setup se automatically governed nahi hote.

## 3. Prerequisites aur addresses

- Signet repository, project dependencies, reachable PostgreSQL database aur application encryption/signing keys.
- Signet mein connection management, agent linking aur approval ke appropriate permissions.
- ServiceNow mein AI Agent Studio, MCP support aur Control Tower setup ke required permissions.
- Existing ServiceNow agent aur required MCP tools.
- Public HTTPS address. Is setup mein ngrok local port **8000** expose karta hai.

| Purpose | Is setup ka value |
| --- | --- |
| Public Signet origin | `https://festive-dealt-talisman.ngrok-free.dev` |
| ServiceNow instance | `https://techsnitchpvtltddemo2.service-now.com` |
| Upstream ServiceNow MCP endpoint | `https://techsnitchpvtltddemo2.service-now.com/sncapps/mcp-server/mcp/perimetra_cmdb_governance_server` |
| ServiceNow → Signet MCP endpoint | `https://festive-dealt-talisman.ngrok-free.dev/v1/mcp/servicenow-cmdb` |
| Signet workload token endpoint | `https://festive-dealt-talisman.ngrok-free.dev/api/v1/identity/token` |
| Signet OAuth callback for ServiceNow authorization | `https://festive-dealt-talisman.ngrok-free.dev/api/v1/plugins/servicenow/callback` |

Apne deployment mein public origin aur instance replace karo. Ngrok address change hone par callback registration, saved public URL aur outbound ServiceNow URLs align karna zaroori hai.

### Local runtime

Repository root se:

```powershell
npm ci
npm run dev
```

Separate terminal mein, ngrok account configured hone ke baad:

```powershell
ngrok http 8000
```

Services: web `8000` when configured in root `.env`, control `4100`, gateways `8100` / `8101`. Vite public requests ko control aur gateway par proxy karta hai. Public hostname root configuration ke allowed hosts mein match hona chahiye.

General runtime configuration ke liye sirf root `.env` use hoti hai. **ServiceNow connection fields UI se database mein save hote hain; unke liye `.env` edit karna zaroori nahi.** Koi `.env.local` ya per-app env file mat banao. Secrets Git ya is guide mein store mat karo.

## 4. ServiceNow ka upstream MCP URL lena

1. ServiceNow **MCP Server Console → Servers** kholo.
2. Existing **Perimetra CMDB Governance Server** card kholo.
3. Card ka **Server URL** copy karo. URL manually agent name se invent nahi karna.
4. Server ke tools check karo.

Is server se ye tools discover hue:

| Tool name | Kaam |
| --- | --- |
| `cmdb_ci_reliability_status` | CI ki reliability/SLO health aur related information |
| `cmdb_ci_reliability_topology` | CI dependencies ke across reliability topology |

Ye tools **agent execution logs ke endpoints nahi hain**.

## 5. ServiceNow-issued OAuth: Signet ko ServiceNow access dena

1. Signet **Add an agent** page par **Why we ask** ke neeche separate **Add ServiceNow AI Agents** card kholo.
2. Form ke top ka dynamic **ServiceNow Redirect URL** copy karo. Public Signet / Gateway URL enter karne par callback us origin ke according update hota hai; entry se pehle browser origin use hota hai.
3. ServiceNow **MCP Server Console → Set up OAuth** kholo.
4. Is delegated connection ke liye **OAuth – Authorization code grant** select karo.
5. Name `Signet MCP Monitoring`, provider name `Signet` use kiya gaya.
6. **Redirect URLs** mein Signet form ka exact callback paste karo.
7. Active checked aur public client unchecked rakha gaya. Client ID aur secret locally copy karo.
8. Is session mein token format **JWT** select hua. Access lifespan `1800` seconds aur refresh lifespan `8640000` seconds tha.
9. Auth scope/API policy aur authorized user's ACL required APIs permit karne chahiye. Session mein scope assignment prompt aaya aur authorization baad mein complete hua; exact final scope policy independently verified nahi hai. Broad access dene ko default fix mat samjho.
10. Save karo.

Signet form mein enter karo:

- Public Signet / Gateway URL.
- ServiceNow instance URL.
- ServiceNow MCP server URL.
- **ServiceNow-issued** OAuth Client ID.
- **ServiceNow-issued** OAuth Client Secret.

**Save and connect** settings persist karta hai aur ServiceNow authorization flow open karta hai. Consent complete karke Signet par wapas aao. **Discover tools** dabao.

Expected: connection authorized aur do tools listed. Initial diagnostic mein `configured: true`, `authorized: true`, lekin `monitoring: false` tha; ye valid distinction hai.

### Connection management

- **All connections** saved connections dynamically list karta hai.
- New connection form blank hota hai; edit selected saved connection load karta hai.
- Edit mein secret blank chhodne par existing secret retained rehta hai.
- Connection identity/settings badalne se authorization/discovery/route invalidate ho sakte hain; reauthorize aur route re-prepare karna pad sakta hai.
- **Remove connection** selected local integration ke config, tokens, pending OAuth state, discovered tools aur associated route/credentials clean karta hai. Agar linked agent ka koi aur ServiceNow link nahi hai to associated monitoring sources bhi remove hote hain. Signet agent registry identity aur ServiceNow ka original agent delete nahi hote.

## 6. Existing ServiceNow AI agent link karna

1. Connection card par **Link existing ServiceNow agent** kholo.
2. **Load agents from ServiceNow** try karo.
3. Access ho to existing agent select karo.
4. Listing denied ho to actual AI Agent Studio record ka **32-character sys_id**, name aur purpose manually enter karke **Link agent to Signet** karo.

Is setup mein:

| Field | Value |
| --- | --- |
| Agent | `Perimetra Agent` |
| Agent sys_id | `cfc64d76ebe38b5078f8bfdffdc0cd14` |
| Agent application | `CPS AI Governance` |

Linking Signet identity register karta hai; ServiceNow mein naya agent create ya original agent modify nahi karta.

### Agent listing par 403

Observed request: `GET /api/now/table/sn_aia_agent` → **HTTP 403**, UI rule `SERVICENOW_PERMISSIONS`.

MCP access Table API read access nahi deta. Authorized user ke table/field ACLs aur OAuth API access policies check karne honge. Session mein automatic listing ka access fix verify nahi hua; actual sys_id se manual linking use hui.

### Read-only agent form

ServiceNow ne warning dikhayi: record `CPS AI Governance` mein hai, current application `Global` hai. Agent tools modify karne ke liye appropriate application scope aur edit permissions use karo; read-only restriction bypass mat karo.

## 7. Activity monitoring alag configure karna

Linked agent card par **Configure activity monitoring** aur **Activity sources and sync** available hain.

1. Authorized execution-data source identify karo; current do CMDB tools is requirement ko satisfy nahi karte.
2. UI mein read-only GET source aur credentials configure karo.
3. Actual execution response ke according mappings configure karo; request linked agent ko filter kare.
4. Sync run karke health, timestamps aur imported agent-specific executions verify karo.

**Pending:** is session mein real execution-data source successfully configured/synced nahi dikhaya gaya. Sirf MCP discovery ke basis par monitoring enabled label nahi dikhna chahiye.

## 8. Signet gateway route aur approval

1. ServiceNow connection card ke **Govern MCP tool calls through Signet** section mein alias `servicenow-cmdb` enter karo.
2. **Prepare gateway route** dabao.
3. Generated gateway URL copy karo; upstream ServiceNow URL ki jagah ye ServiceNow MCP client mein use hoga.
4. Linked agent ki **Review and approval** kholo.
5. **Tools it may call → Add a registered tool** se `mcp://servicenow-cmdb` select karo.
6. Do actions add karo, impact `read`:
   - `cmdb_ci_reliability_status`
   - `cmdb_ci_reliability_topology`
7. Required agent details/data restrictions review karke approval complete karo.

Observed validation errors:

| Error | Meaning / correction |
| --- | --- |
| `a third-party agent needs a mapped REST platform connection or at least one company tool` | Approval ke waqt mapped connection/company tool absent tha. Registered gateway MCP tool aur required actions add kiye gaye |
| `RB-INV-17 only T1/T2 seals may allow Restricted tags (special_category)` | Selected seal tier allowed data category se incompatible tha. Legitimate required data aur tier ko align karna hai; warning bypass nahi karni. Later approval successful screenshot mila, lekin exact field adjustment record nahi hua |

Latest deploy screenshot mein **Shadow** mode aur zero transactions the. Production enforcement ko verified traffic aur policy review ke baad hi assess karo. “Gateway safeguards configured” actual connection proof nahi hai.

## 9. Signet-issued credentials banana aur preserve karna

Agent **Connection / Gateway setup → Connect your agent** mein:

1. Direction **External agent calls Signet OAuth**.
2. Environment `dev` (approved environment se match).
3. Connection label, e.g. `ServiceNow Perimetra Gateway`.
4. **Generate Client ID & Secret**.
5. Credentials ServiceNow outbound provider mein use karo.

Current implementation credentials encrypted database storage se restore karta hai. Page refresh naya client create nahi karta. **Regenerate Client ID & Secret** explicit action hai; replacement ke baad ServiceNow ko update karna zaroori hai.

Older records mein sirf secret hash stored tha. Hash se original plaintext recover nahi ho sakta. UI ka **Save existing secret** original copy verify karke same client/secret encrypted store kar sakta hai. Original copy absent ho to explicit regeneration required hai. Invalid original secret reject hota hai; silent replacement nahi hoti.

Token exchange supports `client_credentials` with JSON or form body. ServiceNow provider ke liye session mein **In Request Body (Form URL-Encoded)** use hua.

ServiceNow delegated upstream token aur Signet workload token dono expire hote hain. Workload platform ko expiry par naya access token obtain karna hota hai. Gateway upstream delegated token refresh support karta hai. Har page refresh par interactive authorization required nahi; revoked/expired refresh grant ya changed OAuth settings par reauthorization lag sakta hai. Discovery/status ke expired-token UI behavior ko har path par independently verify nahi kiya gaya.

## 10. ServiceNow se Signet gateway connect karna

Direct **Add MCP server → OAuth 2.1 → Manual registration → Client Credentials** attempt mein UI ne Authorization URL mandatory dikhaya. Client Credentials ke liye dummy authorization URL invent nahi kiya gaya. Existing connection alias ke through **Others** route use hua.

### A. Outbound OAuth provider

**System OAuth → Application Registry → New → Connect to a third-party OAuth provider**:

| Field | Configured value |
| --- | --- |
| Name | `Signet Perimetra OAuth Provider` |
| Client ID / Secret | Signet-generated agent credentials; ServiceNow-issued credentials nahi |
| Default Grant type | `Client Credentials` |
| Token URL | Public Signet origin + `/api/v1/identity/token` |
| Send Credentials | `In Request Body (Form URL-Encoded)` |
| Active | Checked |
| Application | `Global` in this setup |
| Accessible from | `All application scopes` in this setup |
| Authorization URL | Blank; authorization-code flow yahan use nahi ho raha |
| Token Revocation URL | Blank; unsupported endpoint invent nahi kiya |

ServiceNow auto-generated Redirect URL `/oauth_redirect.do` is client-credentials exchange mein use nahi hota. Isko Signet callback ke saath confuse mat karo.

Save ke baad **OAuth Entity Profiles** related list mein default profile aaya: `Signet Perimetra OAuth Provider default_...`, grant **Client Credentials**.

### B. OAuth credential

**Connections & Credentials → Credentials → New → OAuth 2.0 Credentials**:

- Name `Signet Perimetra OAuth Credential`.
- Active checked.
- OAuth Entity Profile: provider ka generated default profile.

Pehle profile lookup disabled/unavailable tha aur matching provider nahi bana tha. Outbound provider/default profile create hone ke baad credential profile select kiya gaya. Sirf credential type ka naam reference field mein type karne se valid record nahi banta.

### C. Connection alias

**Connection & Credential Aliases → New**:

- Name `Signet Perimetra Gateway`.
- ID `Signet_Perimetra_Gateway`.
- Type **Connection and Credential**.
- Connection type **HTTP**.
- Multiple active connections unchecked in this setup.

Classic list shortcut: instance origin + `/sys_alias_list.do`.

### D. Actual HTTP connection

Alias ke **Connections → New** mein:

| Field | Value |
| --- | --- |
| Name | `Signet Perimetra HTTP Connection` |
| Credential | `Signet Perimetra OAuth Credential` reference select karo |
| Connection alias | `Signet_Perimetra_Gateway` |
| Connection URL | Public Signet origin + `/v1/mcp/servicenow-cmdb` |
| Active | Checked |
| Use MID server | Unchecked; public HTTPS tunnel use ho raha hai |
| URL builder | Unchecked |

Submit/Update karo. Alias ki related list mein **Connections (1)** aur Active **true** verify hua.

### E. AI Agent Studio MCP server

**AI Agent Studio → Settings → Manage MCP servers → New**:

- Name `Signet Perimetra Gateway`.
- Authentication type **Others**.
- Connection and credential alias `Signet_Perimetra_Gateway`.
- Add/Save.

Saved source record:

```text
Table: sn_mcp_server
sys_id: b5284e2eeba4535078f8fbdffdc0cd9c
```

## 11. Current blocker: AI Control Tower sync

**View approval record** par observed popup:

> MCP server not available yet. This MCP server is still being synced to AI Control Tower.

Managed aur Unmanaged MCP inventories check hue. Default filters class aur managed status the. Managed-status condition remove karke combined list mein seven records aaye; Signet gateway absent tha. Original `ServiceNow perimetra_cmdb_governance_server` upstream server hai, Signet gateway ka replacement nahi.

### Logs se kya mila

**System Logs → All**, Created on Today, Message contains `MCP`:

```text
[McpGovernanceHelperSNC] Unable to find CI record for MCP URL:
https://festive-dealt-talisman.ngrok-free.dev/v1/mcp/servicenow-cmdb
Source: sn_ai_governance
```

Doosre server IDs ke liye:

```text
[McpServerDataSyncSNC] Connection record was not found for the source MCP Server ...
```

Visible missing-connection IDs Signet source ID se match nahi hue. Signet sys_id se today's Message filter lagane par no matches aaye. Isliye doosre servers ki warning ko Signet ka confirmed root cause nahi maana gaya.

AlertStreamClassifier/ML solution aur SLI alert warnings bhi dikh rahi thi; unka Signet sync se relation establish nahi hua. Unrelated properties change nahi ki gayi.

### Supplied sync script se confirmed behavior

`McpServerDataSyncSNC.sync()` `sn_mcp_server` records process karta hai. Per-record sequence:

1. `connection_alias` se `OAuthConnectionServiceSNC.getConnectionRecord()`.
2. `connection_url` check.
3. `isSupportedConnectionRecord()` check. Unsupported case **debug** log ke saath skip hota hai.
4. `/sncapps/awh/` URLs skip hote hain; current Signet URL is condition ko match nahi karta.
5. Existing CI lookup; CI absent ho to product model, digital asset aur `cmdb_ci_function_mcp` create karne ka attempt.
6. Connection alias creation / manual registration path.
7. `auth_server_connection` aur `sn_ai_governance_mcp_server_sync` mapping creation.

Isliye **CI missing warning akeli final root cause nahi hai**. Unsupported connection type ek investigation point hai, confirmed diagnosis nahi.

### Next investigation, UI se

1. **System Definition → Script Includes** mein `OAuthConnectionServiceSNC` kholo.
2. In methods ko inspect karo:
   - `getConnectionRecord`
   - `isSupportedConnectionRecord`
   - `getConnectionObjectForManualRegistration`
3. Dekho saved HTTP/OAuth Client Credentials connection supported hai ya koi additional profile field required hai.
4. Scheduled sync invocation aur relevant debug/error diagnostics administrator ke saath inspect karo; exact job name abhi identify nahi hua.
5. Record save, active HTTP connection aur exact alias references already verified hain; unko bina evidence recreate mat karo.

**Abhi tak ServiceNow shipped Script Includes modify nahi hue, sync manually execute nahi hua aur Control Tower registration fix verify nahi hua.** Dummy CI/approval records manually insert karke bypass mat karo.

## 12. Sync resolve hone ke baad final verification

1. Control Tower inventory mein gateway record aur approval record available hon.
2. Required approval authorized reviewer complete kare.
3. Existing **Perimetra Agent → Add tools and information** mein Signet gateway MCP tools attach/select karo, available UI options ke according.
4. Real CI ke valid identifier se `cmdb_ci_reliability_status` test run karo. Native direct tool ki jagah routed gateway tool invoke hona chahiye.
5. Signet **Activity / Scan history / Connection** refresh karke authenticated tool traffic, outcome aur current identity verify karo.
6. Zero requests se nonzero actual traffic aur verified connection evidence aane par hi gateway coverage confirm karo.
7. Execution monitoring ko separate real source sync se verify karo.

**Test Gateway Connection** reachability check hai. Ye agent impersonate nahi karta aur governed tool call evidence generate nahi karta.

## 13. Resolved Signet HTML/JSON error

Observed UI error:

```text
Unexpected token '<', "<!DOCTYPE ..." is not valid JSON
```

Investigation:

- Dev log mein PostgreSQL connection `ECONNRESET` ke baad control process exit hua.
- `concurrently -k` ne remaining local services stop kiye.
- Local port 8000 unreachable tha.
- Public API ne **HTTP 502, text/html** return kiya; ngrok error HTML ko frontend JSON parse kar raha tha.

Resolution performed:

1. `npm run dev` restart kiya.
2. PostgreSQL schema initialization aur control/gateway startup logs successful hue.
3. Public `/healthz` → **200 application/json** verify hua.
4. Unauthenticated `/api/v1/connect/info` → **401 application/problem+json** mila; protected API JSON response restored tha.
5. Frontend API helper ab non-JSON response par URL, HTTP status aur Content-Type ke saath actionable `API_RESPONSE_FORMAT` error deta hai.
6. Typecheck passed.

Server restore hua; underlying transient PostgreSQL network reset ki permanent prevention implement nahi hui. Same outage repeat ho to database/network/process logs inspect karo. Credentials regenerate karna is error ka fix nahi.

## 14. Code map aur validation

| Location | Responsibility |
| --- | --- |
| `apps/control/src/servicenow-mcp-settings.ts` | Tenant-scoped UI configuration CRUD, encrypted secret references |
| `apps/control/src/servicenow-mcp.ts` | Delegated OAuth PKCE/state/callback, connection status |
| `apps/control/src/servicenow-mcp-discovery.ts` | MCP initialize/tools discovery |
| `apps/control/src/servicenow-agents.ts` | Agent listing/linking and coverage |
| `apps/control/src/servicenow-gateway.ts` | Gateway alias preparation and upstream access-token refresh |
| `apps/control/src/identity.ts` | Persisted workload clients, explicit regeneration and legacy secret restoration |
| `apps/control/src/external-connections.ts` | Activity sources, mapping and sync validation |
| `apps/control/src/schema.ts` | Integration/client persistence schema |
| `apps/web/src/components/ServiceNow*.tsx` | Setup, connections, agent linking and route UI |
| `apps/web/src/components/ConnectionSetup.tsx` | Workload credentials UI |
| `apps/web/src/lib/api.ts` | Control API requests and response-format errors |
| `apps/web/vite.config.ts` | Local public-host allowance and control/gateway proxies |

Session mein targeted real-database integration tests for ServiceNow settings, linking, cleanup, analytics and saved credentials passed. Typecheck/build bhi passed during implementation. Is guide ke liye tests dobara run nahi kiye gaye. Full test suite clean hone ka claim nahi: earlier unrelated connector test timeout observed hua tha. Live ServiceNow tool discovery verified hai; real governed Perimetra tool execution pending hai.

Developer validation commands:

```powershell
npm run typecheck
npm run build
node --import tsx --test apps/control/test/servicenow-mcp.test.ts apps/control/test/servicenow-agents.test.ts apps/control/test/saved-client.test.ts
```

Integration tests ko configured test/database access chahiye. OAuth secrets, tokens aur full credential screenshots share/commit mat karo. Is session mein exposed credentials ko replace karna ho to explicit regeneration aur dependent ServiceNow configuration update coordinate karo.
