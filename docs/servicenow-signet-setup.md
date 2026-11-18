# ServiceNow ko Signet se connect karna: easy step-by-step guide

Ye guide existing ServiceNow AI agent ke MCP tool calls Signet gateway se route karne ke liye hai. UI labels instance/release aur permissions ke according thode alag ho sakte hain. Instructions screenshots aur repository ke implemented flow par based hain.

## 1. Pehle samjho: kya connect ho raha hai?

Do connections bante hain:

| Direction | Kaam | Credentials kaun deta hai? |
| --- | --- | --- |
| Signet → ServiceNow | ServiceNow MCP tools discover aur access karna | ServiceNow |
| ServiceNow AI agent → Signet → ServiceNow MCP | Agent ki routed tool calls par Signet policy/evidence lagana | Signet |

Isliye do alag OAuth configurations chahiye. Pehla `Nav Test` record doosre outbound OAuth record ka replacement nahi hai.

Simple terms:

- **MCP server:** tools provide karta hai, jaise incident lookup.
- **AI agent:** tools choose karke kaam karta hai.
- **sys_id:** ServiceNow record ki 32-character identity. Agent link karte waqt AI agent ka ID chahiye, MCP server ka nahi.
- **Gateway alias:** Signet mein registered route ka naam, jaise `servicenow-incidents`.
- **Action name:** tool ka exact technical name, jaise `look_up_incident_records`.
- **Connection alias:** ServiceNow mein URL aur credential ko jodne wala record.

## 2. Is setup ki values aur current status

| Item | Value |
| --- | --- |
| ServiceNow instance | `https://techsnitchpvtltddemo2.service-now.com` |
| ServiceNow MCP server | `Incident MCP Server` |
| Upstream MCP URL | `https://techsnitchpvtltddemo2.service-now.com/sncapps/mcp-server/mcp/incident_mcp_server` |
| Signet gateway alias | `servicenow-incidents` |
| ServiceNow outbound OAuth provider | `Signet Incident OAuth` |
| OAuth credential | `Signet Incident OAuth Credential` |
| ServiceNow connection alias | `Signet_Incident_Gateway` |
| HTTP connection | `Signet Incident HTTP Connection` |
| ServiceNow client-side MCP registration | `Signet Incident Gateway` |

**Current verified state:** upstream OAuth/discovery working; two incident tools discovered; Incident context AI agent manually linked; Signet approval completed; outbound provider, credential, HTTP connection and MCP registration created; Control Tower record shows **Deployed**.

**Current remaining work:** Incident context AI agent is protected and cannot accept a new tool. An existing editable agent must be confirmed, linked/approved with its own Signet identity and credentials, and made to call the gateway. Real governed tool execution and activity monitoring are not yet verified.

Latest screenshot has a different public hostname and selected alias `mcp://signet-demo`. Its association with this incident server is not confirmed. Do not assume it is the same route.

## 3. Before starting

1. Signet must be running and accessible over public HTTPS.
2. ServiceNow must support MCP and AI Agent Studio.
3. Your ServiceNow account needs permissions for the relevant configuration and reviews.
4. Choose an existing AI agent that you can edit. Open **Add tools and information** and confirm **Add tool** is enabled before doing its identity-specific setup.
5. Keep secrets/tokens private. This guide intentionally does not contain them.

For this repository, local startup is:

```powershell
npm ci
npm run dev
```

In a separate terminal, if Signet web is configured on port 8000:

```powershell
ngrok http 8000
```

Only the repository root `.env` is used for file-based environment configuration. ServiceNow connection values are saved through Signet UI; do not create another env file for them.

## 4. Public URL: copy the current address carefully

Use `<PUBLIC_SIGNET_URL>` below to mean your currently working public Signet origin, without a trailing slash or path.

Earlier setup used:

```text
https://festive-dealt-talisman.ngrok-free.dev
```

Latest screenshot shows:

```text
https://another-unplanned-throwing.ngrok-free.dev
```

An address shown in a screenshot is not proof that all saved connections were updated. Confirm the active deployment first.

| Purpose | URL to use |
| --- | --- |
| Signet console/public origin | `<PUBLIC_SIGNET_URL>` |
| ServiceNow OAuth callback | `<PUBLIC_SIGNET_URL>/api/v1/plugins/servicenow/callback` |
| Signet token endpoint | `<PUBLIC_SIGNET_URL>/api/v1/identity/token` |
| Incident gateway MCP endpoint | `<PUBLIC_SIGNET_URL>/v1/mcp/servicenow-incidents` |

Replace the placeholder with the actual HTTPS origin. Do not paste angle brackets into a form.

If ngrok hostname changes, update Signet saved public URL, ServiceNow inbound redirect URL, outbound Token URL and HTTP Connection URL. Reauthorize/re-prepare routes as required by changed settings. Also check the local allowed-host configuration. Do not regenerate client secrets merely because a hostname changed.

## 5. Get the ServiceNow upstream MCP URL

1. ServiceNow → **MCP Server Console → Servers**.
2. Open **Incident MCP Server**.
3. Confirm server is **Active**.
4. Copy its **Server URL**. For this setup:

```text
https://techsnitchpvtltddemo2.service-now.com/sncapps/mcp-server/mcp/incident_mcp_server
```

5. Confirm required tools are enabled. Screenshots show **Incident summarization** and **Look up incident records**.

## 6. Create inbound ServiceNow OAuth: Signet accesses ServiceNow

1. On the MCP server, select **Set up OAuth**.
2. Choose **Authorization code grant** in the inbound integration flow.
3. Fill the form:

| Field | What to enter |
| --- | --- |
| Name | `Nav Test`, or a descriptive name |
| Provider name | `Signet` or your chosen label |
| Redirect URLs | `<PUBLIC_SIGNET_URL>/api/v1/plugins/servicenow/callback` |
| Active | Checked |
| This is a public client | Unchecked |
| Token Format | `JWT` was used in this setup |
| Access token lifespan | `1800` seconds was used |
| Refresh token lifespan | `8640000` seconds was used |

4. Save and securely copy the ServiceNow-issued **Client ID** and **Client secret**.
5. Scope/API policies and the authorizing user's ACLs must permit the required operations. Do not broaden permissions just to hide a permission error.

**Issue seen:** Active was unchecked in the new-record screenshot. It was subsequently checked and the record saved.

Do not replace this record with Signet-issued credentials later. It continues to serve the upstream connection.

## 7. Add the connection in Signet and discover tools

1. Signet → **Add an agent → Add ServiceNow AI Agents**, or open **Settings → Connections/Systems** and use the ServiceNow add button.
2. Fill:

| Signet field | Value |
| --- | --- |
| Public Signet / Gateway URL | `<PUBLIC_SIGNET_URL>` |
| ServiceNow instance URL | `https://techsnitchpvtltddemo2.service-now.com` |
| ServiceNow MCP server URL | URL copied in step 5 |
| OAuth Client ID | ServiceNow-issued ID from step 6 |
| OAuth Client Secret | ServiceNow-issued secret from step 6 |

3. Compare the form's **ServiceNow Redirect URL** with the registered redirect. They must match exactly.
4. Click **Save and connect**.
5. Complete ServiceNow login/consent.
6. Back in Signet, confirm **Authorized** and click **Discover tools**.

Expected discovered tools:

| Display label | Exact action name |
| --- | --- |
| Incident summarization | `incident_summarization` |
| Look up incident records | `look_up_incident_records` |

Discovery proves tool metadata access. It does not prove agent traffic or execution-history monitoring.

## 8. Select and link an existing editable agent

1. In ServiceNow → **AI Agent Studio → Create and manage → AI agents**, open the intended existing agent.
2. Check its description, instructions, tools and active status. Incident-related names alone do not prove it uses your MCP server.
3. Confirm there is no blocking protection policy and **Add tool** is enabled.
4. Copy the AI agent record's **sys_id** using **Copy sys_id** where available, or the record URL's `sys_id` parameter. Do not copy an execution ID or MCP server ID.
5. In Signet's ServiceNow connection → **Link existing ServiceNow agent**.
6. Try **Load agents from ServiceNow**. If permitted, select the correct agent.
7. For manual linking, enter the actual sys_id, exact name and actual purpose, then click **Link agent to Signet**.

Linking registers identity in Signet. It does not create or modify the ServiceNow agent.

### Error: SERVICENOW_PERMISSIONS / HTTP 403

Observed request:

```text
GET /api/now/table/sn_aia_agent
HTTP 403
```

**Meaning:** the authorized account/OAuth policy does not allow the required Table API read. MCP tool permissions do not automatically grant Table API permissions.

**Resolution used:** manually linked the known agent record. Automatic listing permission was not fixed/verified. For listing, an administrator must check table/field read ACLs and OAuth API policies, then retry.

### Error: selected agent is protected/read-only

The selected **Incident context AI agent** showed both:

- Record belongs to IT Service Management AI agent collection while current application is Global.
- Record has a protection policy.

Its **Add tool** button was disabled. Switching scope alone is not a confirmed fix for protection.

**Current outcome:** this agent cannot be used for attaching the Signet gateway through the shown editor. The earlier recommendation did not check editability first.

**Next step:** inspect existing `SignetDemoAgent` or another custom agent; confirm editability before selecting it. No new agent is required if a suitable editable one exists. This replacement has not yet been verified.

The existing incident gateway/OAuth infrastructure can be reused. A different agent needs its own correct Signet link, approval and workload credentials. Do not use the protected agent's credentials to represent another agent. Keep unrelated existing records until their use has been reviewed.

## 9. Prepare the Signet gateway route

1. In the ServiceNow connection, find **Govern MCP tool calls through Signet**.
2. Enter **Gateway alias**: `servicenow-incidents`.
3. Click **Prepare gateway route**.
4. Confirm **Registered tool alias: servicenow-incidents**.
5. Copy the generated MCP URL:

```text
<PUBLIC_SIGNET_URL>/v1/mcp/servicenow-incidents
```

The alias field may initially show a placeholder such as `servicenow-cmdb`; type the intended alias explicitly.

## 10. Review and approval: fill Tools it may call

1. In the linked agent card, click **Review and approval**. This is a button next to **Gateway setup**, not the tool form itself.
2. Open the agent's review/setup form and scroll to **Tools it may call**.
3. Use **Add a registered tool…** to select `mcp://servicenow-incidents`.
4. In the action row, enter `look_up_incident_records`, impact **read**.
5. Click **Add action**. Enter `incident_summarization`, impact **read**.
6. Set **Environments** to `dev` for this test.
7. Review the real data restrictions and required fields. Do not change restrictions only to make validation pass.
8. Save/complete the review and approval through the available workflow.
9. Expected result: deploy page states **Approval is complete**.

**Where do action names come from?** Go to the saved ServiceNow connection → **Discovered tools**. The technical name appears below the display title. The action field is a manual entry field, not a search box.

**Latest screenshot caution:** selected tool was `mcp://signet-demo`. Only enter the incident action names there if that alias actually routes to the same Incident MCP server. Otherwise select/prepare the correct alias. Do not guess from similar names.

Other validation errors recorded in the existing setup notes:

| Error | What to check |
| --- | --- |
| Third-party agent needs a mapped REST platform connection or at least one company tool | Select the registered gateway tool and required actions for this MCP setup |
| RB-INV-17: only T1/T2 seals may allow Restricted tags | Align the legitimate data requirements and seal tier; do not bypass the rule |

## 11. Generate Signet credentials for this agent

1. Open **Gateway setup**, or the approved agent's deploy page.
2. Under **Connect your agent**:

| Field | Value |
| --- | --- |
| Connection direction | `External agent calls Signet OAuth` |
| Environment | `dev`, matching approval |
| Connection label | `ServiceNow Incident Test` |

3. Click **Generate Client ID & Secret**.
4. Save the generated credentials securely. These are Signet-issued credentials, separate from `Nav Test`.
5. Copy the displayed token endpoint. It must use the current public origin:

```text
<PUBLIC_SIGNET_URL>/api/v1/identity/token
```

A token alone does not mark the agent connected. Regenerating credentials requires updating the corresponding ServiceNow outbound provider.

## 12. Create outbound OAuth provider in ServiceNow

1. **All → System OAuth → Application Registry → New**.
2. Select **Connect to a third party OAuth Provider - Outbound**.
3. Fill:

| Field | Value |
| --- | --- |
| Name | `Signet Incident OAuth` |
| Client ID / Client Secret | Signet-generated credentials from step 11 |
| Default Grant type | `Client Credentials` |
| Token URL | `<PUBLIC_SIGNET_URL>/api/v1/identity/token` |
| Send Credentials | `In Request Body (Form URL-Encoded)` |
| Active | Checked |
| Public Client | Unchecked |
| Use mutual authentication | Unchecked |

4. Use the lock icon to unlock the Token URL field if necessary.
5. Leave **Authorization URL**, **Token Revocation URL** and **OAuth API Script** empty for this setup. Keep auto-generated Redirect URL unchanged.
6. Click **Submit**, reopen the saved record.
7. Under **OAuth Entity Profiles**, confirm the generated `Signet Incident OAuth default_profile` with grant **Client Credentials**.

Do not edit `Nav Test` to do this. That is the separate inbound provider.

## 13. Create OAuth credential and request a token

1. **Connections & Credentials → Credentials → New → OAuth 2.0 Credentials**.
2. Fill:

| Field | Value |
| --- | --- |
| Name | `Signet Incident OAuth Credential` |
| Active | Checked |
| OAuth Entity Profile | Select `Signet Incident OAuth default_profile` using lookup |
| Connect to OAuth Server via MID Server | Unchecked |

3. Keep other fields at their existing values and **Submit**.
4. Reopen the saved credential.
5. Under **Related Links**, click **Get OAuth Token**.

### Token messages seen

- **Access or Refresh tokens are not available:** credential existed but no token was available. Use **Get OAuth Token** after checking provider settings.
- After requesting, banner changed to **Access token is available but will expire soon**. This confirms a token was stored, not that gateway tool traffic worked.
- The displayed expiry was `2026-11-17 23:42:13`. Do not treat that old timestamp as evidence of a currently valid token. Request a fresh token before testing and inspect the resulting expiry/error. If a freshly issued token appears expired, inspect response lifetime and instance/display timezone before diagnosing a clock problem.

For token-request failures, capture the actual status/response without secrets and check public URL, provider grant and agent-specific Signet credentials. No specific token-request failure response was shown in this flow.

## 14. Create ServiceNow Connection & Credential Alias

1. **All → Connection & Credential Aliases → New**.
2. Fill:

| Field | Value |
| --- | --- |
| Name | `Signet Incident Gateway` |
| ID | Auto-generated; saved value was `Signet_Incident_Gateway` |
| Type | `Connection and Credential` |
| Connection type | `HTTP` |
| Support Multiple Active Connections | Unchecked |
| Parent Alias / Configuration Template | Empty |
| Default Retry Policy | Keep existing default |

3. Click **Submit** and reopen the saved alias.

If ID is grey, do not try to force-edit it. Use the generated ID in later references.

## 15. Add the actual HTTP connection

1. In the alias record, open **Connections → New**. Use the New button inside this related list.
2. Fill:

| Field | Value |
| --- | --- |
| Name | `Signet Incident HTTP Connection` |
| Credential | Select `Signet Incident OAuth Credential` using lookup |
| Connection alias | `Signet_Incident_Gateway` |
| Connection URL | `<PUBLIC_SIGNET_URL>/v1/mcp/servicenow-incidents` |
| Active | Checked |
| Domain | Keep `global` |
| URL builder | Unchecked |
| Use MID server | Unchecked |
| Connection timeout | Left empty in this setup |

3. **Submit**.
4. Verify alias shows **Connections (1)**, **Active true**, correct credential and **Use MID server false**.
5. Open the connection to verify the full URL path; the Host column alone does not show it.

## 16. Register Signet MCP gateway in AI Agent Studio

1. **AI Agent Studio → Settings → Manage MCP servers → New**.
2. Enter **Signet Incident Gateway**.
3. Choose authentication **Others** where offered.
4. Select connection alias `Signet_Incident_Gateway`.
5. **Add/Save**.
6. Reopen the record and verify server name and alias, then click **View approval record**.

The existing **Signet Perimetra Gateway** is a separate setup. Do not replace it for this incident test.

### Error: MCP server not available yet

Popup said the MCP server was still being synced to AI Control Tower.

**Resolution observed:** a later attempt opened the Control Tower record successfully. The exact sync mechanism/root cause and elapsed time were not established. No OAuth recreation, shipped-script modification or manual CI insertion was shown as necessary.

If still pending: wait a few minutes, refresh and retry. If persistent, ask the AI steward/admin to inspect this exact server's registration/sync status and logs. An earlier Perimetra investigation had missing-CI warnings, but that does not establish the cause for this incident server. Do not copy unrelated log errors as its diagnosis.

## 17. AI Control Tower review

1. Confirm the record is **Signet Incident Gateway** and its related variant has the expected gateway MCP URL.
2. Click **Start review**. Status changed from **AI steward review** to **In review**, phase **Assess**.
3. Open **Lifecycle**. **Related Variants** only shows connection details, not the review workflow.
4. Review the **Assess** stage. In this setup it showed **No onboarding tasks created** and buttons **Create new task** / **Mark as complete**.
5. If assessment work is needed, create/assign the task. An empty list does not mean assessment is complete.
6. The authorized reviewer completes the applicable assessment, build/test and deployment requirements before marking each stage complete.

The supplied final Control Tower screenshot shows **Assess**, **Build and test**, and **Deploy** marked **Complete**, lifecycle status **Deployed**. Intermediate task evidence was not supplied. This proves the displayed lifecycle state, not a successful Signet tool execution.

## 18. Attach gateway tools to the existing editable agent (pending)

1. **AI Agent Studio → Create and manage → AI agents**.
2. Open the verified editable existing agent.
3. Open **Add tools and information → Add tool**.
4. Inspect the available MCP option, choose **Signet Incident Gateway** if available, and select the required incident tools.
5. Review the actual instructions so the test invokes gateway-provided tools rather than existing direct/native tools.
6. Save through the available UI.

Exact picker screens after Add tool have not been supplied. Do not assume the buttons or claim tools attached without checking.

If **Add tool** is disabled and protection policy is displayed, stop editing that record and select an editable agent. The protected **Incident context AI agent** cannot complete this step through the shown UI.

## 19. Run one real test and verify Signet (pending)

1. Keep Signet/ngrok running. Confirm current public URLs and a valid outbound token.
2. Use the agent's testing UI and a real accessible test incident number.
3. Example request: `Use the Signet gateway lookup tool to retrieve incident <actual incident number> and summarize the result. Do not modify records.` Replace the placeholder first.
4. Inspect execution/tool details to confirm a gateway-attached action actually ran. A prompt alone cannot guarantee routing.
5. In Signet, refresh the agent's **Connection activity and diagnostics / Activity** views.
6. Confirm authenticated gateway tool traffic under the correct agent, route, action and outcome. Investigate errors before claiming success.

**Success requires:** a real routed request and Signet evidence. OAuth token creation, Control Tower Deployed status, tool discovery, or zero-traffic approval screens are insufficient.

**Test Gateway Connection** checks reachability; it does not impersonate the external agent or generate a governed tool call. Keep **Shadow** while validating; changing to enforce is a separate rollout decision.

## 20. Activity monitoring is a separate setup (pending)

The linked-agent card can show **Gateway enforcement not verified** and **Activity monitoring not configured or not verified** independently.

For execution-history import:

1. Open **Configure activity monitoring**.
2. Supply the documented read-only execution/activity API and credentials.
3. Scope the execution request to the linked agent and map the actual response fields.
4. Use **Activity sources and sync** to run/verify sync and agent-specific imported executions.

No working execution-history source was demonstrated. Incident lookup and summarization tools do not automatically provide agent execution logs. Do not invent an activity endpoint or mark monitoring complete from tool discovery.

## 21. Troubleshooting quick reference

| Symptom | Meaning / next action | Observed outcome |
| --- | --- | --- |
| OAuth setup required | Complete ServiceNow inbound authorization-code setup and save Signet settings | Upstream authorization/discovery completed |
| AI agent list HTTP 403 | Check Table API ACL/API policies; link known actual agent manually if needed | Manual link completed; listing permission unresolved |
| Cannot find Review and approval | Look in linked agent card beside Gateway setup | Button located |
| Cannot search action name | Copy technical name from Discovered tools; enter manually | Two incident action names identified |
| Different tool alias selected | Verify its upstream route before entering actions | `signet-demo` mapping not confirmed |
| No OAuth token | Request through credential's Get OAuth Token | Stored-token banner appeared |
| Token expires soon/old expiry | Request fresh token and verify lifetime | Current valid token not established by old banner |
| MCP still syncing | Retry then inspect exact server's sync with admin | Incident record later appeared in Control Tower |
| No onboarding tasks | Review requirements; create tasks if needed | Later screenshot shows lifecycle Deployed |
| Add tool greyed out | Protected agent cannot be edited through shown UI | Existing editable replacement still needed |
| Gateway enforcement not verified | Need real authenticated traffic for correct identity | Real execution not yet demonstrated |
| Monitoring not configured | Need separate execution-history source and successful sync | Pending |
| ngrok hostname changed | Update all URL references consistently | Latest screen uses a different origin; alignment unverified |

### Earlier local-runtime error: HTML returned instead of JSON

If the console reports `Unexpected token '<', "<!DOCTYPE ..." is not valid JSON`, check whether ngrok returned HTTP 502 HTML because the control process stopped. Verify the local MongoDB replica set and inspect the control process error.

Restoring `npm run dev` restored public `/healthz` to HTTP 200 JSON and protected API responses to JSON. The frontend helper also reports non-JSON status/content type more clearly. Permanent prevention of the database network reset was not established. If repeated, inspect database/network/process logs; regenerating OAuth credentials does not fix a stopped server.

## 22. Final checklist

- [ ] Current public URL matches callback, saved Signet settings, token URL and HTTP MCP connection URL.
- [ ] ServiceNow upstream connection is Authorized and exact incident tools discovered.
- [ ] Existing selected agent is editable; Add tool is enabled.
- [ ] Correct AI agent sys_id is linked in Signet.
- [ ] Registered alias points to the intended incident MCP server.
- [ ] Required exact actions are approved for the intended environment.
- [ ] Outbound OAuth uses that same agent's Signet-issued credentials.
- [ ] HTTP connection is active and references the intended credential/alias.
- [ ] Control Tower lifecycle requirements are completed by the appropriate reviewer.
- [ ] Gateway tools are attached to the editable agent.
- [ ] Real tool execution is visible in Signet for the correct identity.
- [ ] Activity monitoring is verified separately if required.

This is a configuration guide; no code/test changes are required to follow it. Documentation alone does not validate a live connection. Keep secrets out of shared screenshots, this file and Git.
