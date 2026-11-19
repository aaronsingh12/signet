# ServiceNow AI agent ko Signet se connect karna

Easy Hinglish guide: basics, complete connection steps, real incident test aur faced errors. UI labels ServiceNow release aur permissions ke according thode alag ho sakte hain.

Native chat prompt/response blocking ke liye separate [ServiceNow Guardian setup](servicenow-guardian-setup.md) follow karo. Ye MCP guide akeli native model traffic intercept nahi karti.

- [Part A - Basics aur preparation](#part-a---basics-aur-preparation)
- [Part B - Complete connection steps](#part-b---complete-connection-steps)
- [Part C - Pehle try kiya manual connection path](#part-c---pehle-try-kiya-manual-connection-path)
- [Part D - Faced errors aur resolutions](#part-d---faced-errors-aur-resolutions)
- [Part E - Final verification checklist](#part-e---final-verification-checklist)

## Current result

| Check | Evidence |
| --- | --- |
| Signet -> ServiceNow connection | OAuth Authorized; two incident tools discovered |
| Editable agent | Protected original ki copy banayi gayi |
| Copy onboarding | Copy ki sys_id linked; Signet approval aur credentials configure hue |
| Control Tower | Copy agent aur pehle gateway asset ke Managed/Deployed screenshots mile |
| Direct OAuth MCP registration | `Navin` record Authenticate hua; warning hati aur Re-authenticate button aaya |
| Agent mein tools | Incident summarization tool aur input definition load hue |
| ServiceNow real test | `INC0010012` summarization Completed; result mein `success: True` |
| Signet execution evidence | Same call ka final Activity screenshot abhi supplied nahi; verification baaki |
| Execution-history monitoring | Separate source ka successful sync verify nahi hua |

**ServiceNow tool test successful hai. Full gateway coverage ka final proof correct agent/action/route ki Signet Activity entry hai.**

# Part A - Basics aur preparation

## A1. Kya connect ho raha hai?

```text
ServiceNow AI agent (Copy)
    -> Signet gateway
    -> ServiceNow Incident MCP Server
    -> Tool result
```

Do alag OAuth connections chahiye:

| Connection | Kaam | Client ID/Secret kaun deta hai? |
| --- | --- | --- |
| Signet -> ServiceNow | Upstream MCP tools discover/access karna | ServiceNow |
| ServiceNow -> Signet | Agent ki routed requests authenticate karna | Signet |

Pehla `Nav Test` OAuth record doosre connection ka replacement nahi hai. Credentials interchange mat karo.

## A2. Simple terms

| Term | Meaning |
| --- | --- |
| MCP server | Tools provide karne wala endpoint |
| AI agent | Instructions follow karke tools chalane wala agent |
| sys_id | ServiceNow record ki 32-character identity |
| Gateway tool alias | Signet route ka naam, jaise `servicenow-incidents` |
| Action name | Exact technical tool name, jaise `incident_summarization` |
| Connection alias | ServiceNow record jo connection aur credential ko reference karta hai |
| Authorization URL | Browser login/consent shuru karne ka endpoint |
| Token URL | Code ya credentials exchange karke access token lene ka endpoint |
| Callback / Redirect URL | OAuth ke baad browser jahan wapas aata hai |
| PKCE S256 | Authorization aur token exchange ko matching verifier se bind karta hai |
| Supervised | Tool execution se pehle approval maangta hai |

AI agent, MCP server aur execution ke sys_id alag hain. Signet linking mein **AI agent** ka ID chahiye.

## A3. Is setup ki values

| Item | Value |
| --- | --- |
| ServiceNow instance | `https://techsnitchpvtltddemo2.service-now.com` |
| Confirmed public Signet origin | `https://festive-dealt-talisman.ngrok-free.dev` |
| Upstream server | `Incident MCP Server` |
| Upstream URL | `https://techsnitchpvtltddemo2.service-now.com/sncapps/mcp-server/mcp/incident_mcp_server` |
| Signet gateway alias | `servicenow-incidents` |
| Signet registered tool | `mcp://servicenow-incidents` |
| Protected original | `Incident context AI agent` |
| Previously linked original sys_id | `ff52e1f12bd3f6100171f8014391bf98` |
| Editable copy | `Incident context AI agent (Copy)` |
| Copy sys_id | `6dfcea3e0f2457507e34bec300d1b216` |
| Successful direct OAuth MCP record | `Navin` |
| Test incident | `INC0010012` |

`<PUBLIC_SIGNET_URL>` neeche current public Signet origin ka placeholder hai. Is setup mein festive ngrok address use hua. Form mein actual URL paste karo, angle brackets nahi.

## A4. URL reference

| Purpose | URL |
| --- | --- |
| Public Signet origin | `<PUBLIC_SIGNET_URL>` |
| ServiceNow-issued inbound OAuth callback | `<PUBLIC_SIGNET_URL>/api/v1/plugins/servicenow/callback` |
| ServiceNow agent ke liye Signet MCP URL | `<PUBLIC_SIGNET_URL>/v1/mcp/servicenow-incidents` |
| Signet Authorization URL | `<PUBLIC_SIGNET_URL>/api/v1/identity/authorize` |
| Signet Token URL | `<PUBLIC_SIGNET_URL>/api/v1/identity/token` |
| Is outbound ServiceNow flow ka callback | `https://techsnitchpvtltddemo2.service-now.com/oauth_redirect.do` |

Last callback actual Authenticate request ke `redirect_uri` se confirm hua. Doosre instance/client mein uska actual supplied callback use karo.

Ngrok hostname badle to Signet public/Hosted addresses, ServiceNow inbound redirect, outbound Authorization/Token URLs aur HTTP MCP URL align karo. Allowed-host configuration bhi check karo. Sirf hostname badalne par secret regeneration zaroori nahi.

## A5. Prerequisites aur startup

- Repository dependencies aur configured MongoDB replica set available hon.
- Signet console/control/gateway public HTTPS se reachable hon.
- ServiceNow mein MCP, AI Agent Studio aur required configuration/review permissions hon.
- Appropriate Signet linking, approval aur identity-management permissions hon.
- Agent editor mein Add tool enabled ho; protected agent ko pehle identify karo.
- Client secrets/tokens private rakho; shared screenshots mein hide karo.

Repository root se:

```powershell
npm ci
npm run dev
```

Separate terminal mein, configured web port expose karo. Is setup mein port 8000 tha:

```powershell
ngrok http 8000
```

File-based environment config sirf repository root `.env` mein rakho. `.env.local` ya per-app env file mat banao. ServiceNow integration fields Signet UI mein save hote hain. Secrets Git/docs mein mat rakho.

# Part B - Complete connection steps

Ye primary sequence direct **OAuth 2.1 Manual Registration + Authorization Code** path use karta hai, jis par tool discovery aur summarization test successful hue.

## Step 1. ServiceNow upstream MCP URL lo

1. ServiceNow -> **MCP Server Console -> Servers** kholo.
2. **Incident MCP Server** kholo; server Active hona chahiye.
3. **Server URL** copy karo. A3 mein is setup ka URL diya hai.
4. Required tools enabled check karo: **Incident summarization** aur **Look up incident records**.

MCP endpoint ko AI agent ke naam se invent mat karo.

## Step 2. ServiceNow inbound OAuth banao

1. Server par **Set up OAuth** kholo.
2. Inbound **Authorization code grant** choose karo.
3. Fill:

| Field | Value |
| --- | --- |
| Name | `Nav Test`, ya descriptive label |
| Provider name | `Signet`, ya chosen label |
| Redirect URLs | `<PUBLIC_SIGNET_URL>/api/v1/plugins/servicenow/callback` |
| Active | Checked |
| This is a public client | Unchecked |
| Token Format | Is setup mein `JWT` |
| Access token lifespan | Is setup mein `1800` seconds |
| Refresh token lifespan | Is setup mein `8640000` seconds |

4. Save karo; ServiceNow-issued Client ID aur Secret securely copy karo.
5. Authorized user's ACLs/OAuth API policies required access permit karni chahiye. Broad access default fix nahi hai.

## Step 3. Signet mein connection save, authorize aur discover karo

1. Signet -> **Settings -> Connections/Systems -> Add ServiceNow AI Agents** kholo. Add an agent page par bhi button ho sakta hai.
2. Fill:

| Signet field | Value |
| --- | --- |
| Public Signet / Gateway URL | `<PUBLIC_SIGNET_URL>` |
| ServiceNow instance URL | `https://techsnitchpvtltddemo2.service-now.com` |
| ServiceNow MCP server URL | Step 1 ka copied upstream URL |
| OAuth Client ID | Step 2 ka ServiceNow-issued ID |
| OAuth Client Secret | Step 2 ka matching secret |

3. Generated **ServiceNow Redirect URL** ko Step 2 registration se exactly match karo.
4. **Save and connect** -> ServiceNow login/consent complete karo.
5. Signet par **Authorized** verify karo.
6. **Discover tools** dabao.

| Display label | Exact action name |
| --- | --- |
| Incident summarization | `incident_summarization` |
| Look up incident records | `look_up_incident_records` |

Technical names approval mein use honge. Discovery execution-history monitoring nahi hai.

## Step 4. Editable agent select karo

1. ServiceNow -> **AI Agent Studio -> Create and manage -> AI agents** kholo.
2. Description/instructions/tools check karo; sirf incident-related name enough nahi.
3. **Add tools and information** mein **Add tool** enabled verify karo.
4. Is setup ka original protected tha. User ne duplicate **Incident context AI agent (Copy)** create kiya.
5. Duplicate banana ho to available record actions mein copy option inspect karo. Exact copy-menu label ka screenshot capture nahi hua tha.
6. Copy kholkar editability verify karo aur uska actual sys_id copy karo.

Description ka "strictly read-only" incident data modify na karne ki instruction hai; editor protection policy se alag hai.

## Step 5. Copy ko Signet mein link karo

1. Signet ServiceNow connection -> **Link existing ServiceNow agent**.
2. **Load agents from ServiceNow** permitted ho to correct agent select karo.
3. Listing HTTP 403 ho to actual known record manually link karo:

| Field | Value |
| --- | --- |
| ServiceNow AI agent sys_id | `6dfcea3e0f2457507e34bec300d1b216` |
| Agent name | `Incident context AI agent (Copy)` |
| What does this agent do? | `Retrieves incident details and related context without modifying records.` |

4. **Link agent to Signet** dabao.

Copy automatically onboard nahi hoti. Original ki linking copy par apply nahi hoti. Linking identity register karti hai; original ServiceNow record modify nahi karti.

## Step 6. Signet gateway route prepare karo

1. Connection mein **Govern MCP tool calls through Signet** kholo.
2. **Gateway alias:** `servicenow-incidents` type karo.
3. **Prepare gateway route** dabao.
4. Verify **Registered tool alias: servicenow-incidents**.
5. Generated URL copy karo:

```text
https://festive-dealt-talisman.ngrok-free.dev/v1/mcp/servicenow-incidents
```

Same upstream ka existing route reuse kar sakte ho. Gateway alias isi section mein milta hai; ServiceNow connection alias alag cheez hai.

## Step 7. Copy ki Review and approval complete karo

1. Linked copy ke card ka **Review and approval** button dabao.
2. Review/setup form mein **Tools it may call** tak scroll karo.
3. **Add a registered tool...** se `mcp://servicenow-incidents` select karo.
4. First action aur **Add action** se second action bharo:

| Action name | Impact |
| --- | --- |
| `look_up_incident_records` | `read` |
| `incident_summarization` | `read` |

5. **Environments:** `dev`.
6. Actual required data permissions, prohibited categories, limits aur review fields check karo.
7. Save aur required approval workflow complete karo.
8. Deploy screen par **Approval is complete** verify karo.

Action field search box nahi hai. Names Step 3 ke Discovered tools se copy karke manually enter karo. Sensitive-data restrictions sirf validation pass karne ke liye relax mat karo.

## Step 8. Copy ke Signet credentials lo

1. Copy card -> **Gateway setup**, ya approved agent Deploy page kholo.
2. **Connect your agent** mein:

| Field | Value |
| --- | --- |
| Connection direction | `External agent calls Signet OAuth` |
| Environment | `dev` |
| Connection label | `Incident Copy Test` |

3. **Generate Client ID & Secret** dabao; already saved hain to wahi restore honge.
4. Copy agent ke credentials securely save karo. Original agent ya Nav Test ke credentials yahan use nahi honge.
5. Dynamic Authorization/Token URLs configured **Hosted Signet control address** se bante hain.

## Step 9. Signet mein ServiceNow callback register karo

1. Gateway setup -> **OAuth Authorization Code** section kholo.
2. **External platform callback URL** mein actual outbound callback bharo:

```text
https://techsnitchpvtltddemo2.service-now.com/oauth_redirect.do
```

3. **Save callback URL** dabao.
4. Same Client ID ke liye callback save hona chahiye jo ServiceNow mein use hoga.

Ye inbound `/api/v1/plugins/servicenow/callback` nahi hai. Callback save/change is client ke pending requests, codes aur refresh tokens invalidate karta hai; Authenticate dobara karo.

## Step 10. Direct OAuth 2.1 MCP registration banao

1. **AI Agent Studio -> Settings -> Manage MCP servers -> New**.
2. Fill:

| Field | Value |
| --- | --- |
| Name | Is setup mein `Navin` |
| Authentication type | `OAuth 2.1` |
| MCP server URL | `<PUBLIC_SIGNET_URL>/v1/mcp/servicenow-incidents` |

3. **Next** dabao; next form:

| Field | Value |
| --- | --- |
| Client registration type | `Manual Registration` |
| Grant type | `Authorization Code` |
| Token authentication method | `Client Secret Basic` |
| Client ID | Step 8 ka copy agent ID |
| Client secret | Step 8 ka matching secret |
| Auth scopes | `mcp`, ya empty; granted scope mcp hai |
| Authorization URL | `<PUBLIC_SIGNET_URL>/api/v1/identity/authorize` |
| Token URL | `<PUBLIC_SIGNET_URL>/api/v1/identity/token` |
| Token Revocation URL | Blank; public endpoint advertised nahi hai |

4. **Add/Save** dabao.
5. Auto-generated connection alias rehne do. Navin mein `AutoGen_Navin_..._OAuthProviderAlias` bana tha.

Signet mein PKCE S256 mandatory hai. Actual ServiceNow request mein S256 challenge aayi. Dynamic Client Registration implement nahi hai; Manual Registration use karo.

## Step 11. Navin Authenticate karo

1. Saved **Navin** record par **Authenticate** dabao.
2. Signet login khule to appropriate owner/administrator se sign in karo.
3. Consent page par agent name, callback aur environment check karo.
4. **Allow access** dabao; ServiceNow par wapas aane do.
5. Token warning hatna aur **Re-authenticate** dikhna check karo.

Code five-minute, single-use hai. Refresh token rotate hota hai; external client ko latest replacement preserve karna chahiye. Token alone real gateway call ka proof nahi.

## Step 12. AI Control Tower review verify karo

1. MCP record ka **View approval record** kholo.
2. Gateway MCP asset aur copied AI agent alag records hain; correct identity/URL verify karo.
3. Applicable workflow: **Start review -> Lifecycle**.
4. Assess, Build and test, Deploy ke actual required tasks/reviews complete karo.
5. Authorized reviewer hi completed work ko **Mark as complete** kare.

Empty task list assessment-complete proof nahi. Screenshots mein pehle Signet Incident Gateway aur baad mein copy agent Managed/Deployed dikhte hain. Navin ka status uske apne record par check karo; old gateway approval ko naye record ki approval mat samjho.

## Step 13. Copy mein Navin ka tool attach karo

1. **Create and manage -> AI agents -> Incident context AI agent (Copy)**.
2. **Add tools and information -> Add tool -> MCP server tool**.
3. Server: **Navin**.
4. Tool: **Incident summarization**.
5. Input definition load hogi: `incidentNumber`, type `string`.
6. Grey input definition mein abhi actual incident number nahi bharna; execution ke waqt value jayegi.
7. Settings:

| Field | Value |
| --- | --- |
| Name | Existing `Incident summarization`, ya `Signet Incident Summarization` |
| Tool description | Existing summary description; gateway use clearly describe kar sakte ho |
| Execution mode | `Supervised` |
| Display output | On |

8. Dialog mein **Add/Save**; agent editor mein **Save and continue**.
9. Required agent configuration save karke correct active version test karo.
10. Lookup required ho to Navin se **Look up incident records** separately add karo. Session mein summarization attachment/test verify hua.

Copy mein inherited native scripts bhi hain. Execution details mein intended MCP tool verify karo; similar display name routing ka proof nahi.

## Step 14. INC0010012 ka real test

1. **Testing -> Manual Test** kholo.
2. Select:

| Field | Value |
| --- | --- |
| Test type | `AI agent or workflow` |
| Name | `Incident context AI agent (Copy)` |
| Version | Correct saved active version; screenshot mein `1 - V1 (Active)` |

3. Task paste karo:

```text
Summarize incident INC0010012 using the MCP incident summarization tool from the Navin server connected through Signet.

Pass incidentNumber as INC0010012. Request approval before executing the supervised tool. Do not modify the incident. If the tool fails, report the error instead of using another tool.
```

4. **Continue to test chat response** dabao.
5. Agent permission maange to incident/action verify karke **Yes** do.
6. **AI agent decision logs** mein tool details inspect karo.

Observed: **Tool - Incident summarization: Completed**, result mein `success: True`, aur incident summary returned. Summary mein mentioned past record changes ko is test ke writes mat samjho.

Apne instance par accessible real test incident use karo.

## Step 15. Signet mein same real request verify karo

1. Signet -> **Incident context AI agent (Copy)** kholo.
2. **Activity / Connection activity and diagnostics** refresh karo.
3. Test time ki entry check karo:

| Check | Expected |
| --- | --- |
| Agent | Copy ki identity; original nahi |
| Action | `incident_summarization` |
| Route | `servicenow-incidents` |
| Outcome | Actual status/result shown in evidence |

Final Signet evidence conversation mein abhi nahi mila. **Test Gateway Connection** reachability check hai; external agent impersonate karke governed tool call create nahi karta. Token, discovery aur Deployed labels execution proof nahi hain.

## Step 16. Activity monitoring alag configure karo, agar required ho

1. Linked agent -> **Configure activity monitoring**.
2. Documented read-only execution/activity API aur credentials do.
3. Request ko correct copy agent par scope karo; actual response fields map karo.
4. **Activity sources and sync** run karke imported agent-specific executions verify karo.

Incident lookup/summarization execution-history API nahi hain. Working history sync verify nahi hua. Native tools/model calls jo Signet bypass karte hain automatically intercept nahi hote. Shadow se enforce move karna separate rollout decision hai.

# Part C - Pehle try kiya manual connection path

Ye **Client Credentials + manually created connection alias** path bhi try hua tha. Fresh direct Navin flow follow kar rahe ho to ye records dobara banana zaroori nahi. Old path mein no-tools issue aaya; exact root cause establish nahi hua. Baad mein Part B wale Authorization Code flow par discovery aur real test successful hue.

## C1. Outbound OAuth provider

1. **All -> System OAuth -> Application Registry -> New**.
2. **Connect to a third party OAuth Provider - Outbound** select karo.
3. Fill:

| Field | Value |
| --- | --- |
| Name | `Signet Incident OAuth` |
| Client ID / Secret | Intended copy agent ke Signet-issued credentials |
| Default Grant type | `Client Credentials` |
| Token URL | `<PUBLIC_SIGNET_URL>/api/v1/identity/token` |
| Send Credentials | `In Request Body (Form URL-Encoded)` |
| Active | Checked |
| Public Client / Use mutual authentication | Unchecked |
| Authorization URL / Token Revocation URL / OAuth API Script | Blank |

Token URL locked ho to lock icon se unlock karo. Auto-generated Redirect URL unchanged rakho. Submit/reopen karke **OAuth Entity Profiles** mein `Signet Incident OAuth default_profile`, grant Client Credentials verify karo.

Ye Nav Test inbound record se alag provider hai.

## C2. OAuth credential aur token

1. **All -> Connections & Credentials -> Credentials -> New -> OAuth 2.0 Credentials**.
2. Name: `Signet Incident OAuth Credential`.
3. Active checked; **OAuth Entity Profile** lookup se generated default profile select karo.
4. **Connect to OAuth Server via MID Server** unchecked.
5. Submit/reopen -> **Related Links -> Get OAuth Token**.

Baad mein credential kholna ho to All mein Credentials search karo; Name se record find karke open karo. Application Registry provider aur Credential record alag hain.

## C3. Connection alias banao

1. **Connection & Credential Aliases -> New**.
2. Fill:

| Field | Value |
| --- | --- |
| Name | `Signet Incident Gateway` |
| ID | Auto-generated; saved value `Signet_Incident_Gateway` |
| Type | `Connection and Credential` |
| Connection type | `HTTP` |
| Support Multiple Active Connections | Unchecked |
| Parent Alias / Configuration Template | Blank |
| Default Retry Policy | Existing default |

3. Submit aur saved alias reopen karo. Grey ID force-edit mat karo.

## C4. Actual HTTP connection attach karo

1. Alias record ke neeche **Connections -> New** dabao.
2. Fill:

| Field | Value |
| --- | --- |
| Name | `Signet Incident HTTP Connection` |
| Credential | Lookup se `Signet Incident OAuth Credential` |
| Connection alias | `Signet_Incident_Gateway` |
| Connection URL | `<PUBLIC_SIGNET_URL>/v1/mcp/servicenow-incidents` |
| Active | Checked |
| Domain | `global` |
| URL builder / Use MID server | Unchecked |
| Connection timeout | Is setup mein blank |

3. Submit. Alias par **Connections (1)**, Active true, correct credential verify karo.
4. Full URL ke liye connection record open karo; Host column alone path nahi dikhata.

## C5. Existing alias se MCP server register karo

1. **AI Agent Studio -> Settings -> Manage MCP servers -> New**.
2. Name **Signet Incident Gateway**, authentication **Others**.
3. Connection alias **Signet_Incident_Gateway** select karke save karo.
4. Applicable Control Tower status/review correct record/URL ke liye verify karo.

**Original se copy identity switch:** old provider ka Client ID/Secret copy ke credentials se update karke credential ka Get OAuth Token dobara kiya gaya. Shared provider update us connection ke consumers ki identity bhi badalta hai. Direct Navin registration ka auto-generated alias alag hai.

# Part D - Faced errors aur resolutions

Har entry mein observed problem aur actual known outcome diya hai. Jo root cause establish nahi hua, use confirmed fix ke roop mein present nahi kiya gaya.

## Error 1. OAuth setup required / Active unchecked

**Kahan:** upstream Incident MCP Server aur inbound OAuth form.

**Meaning:** client access ke liye OAuth setup required tha; initial new-record form mein Active unchecked tha.

**Action:** inbound Authorization Code form complete, Active checked, Save; Signet settings aur consent complete.

**Result:** connection Authorized aur tools discovered.

## Error 2. SERVICENOW_PERMISSIONS - AI agent listing HTTP 403

```text
GET /api/now/table/sn_aia_agent
HTTP 403
```

**Meaning:** authorized user ke table/field ACLs ya OAuth API policies Table API read permit nahi kar rahe the. MCP tool access automatically Table API listing access nahi deta.

**Action used:** actual known agent sys_id/name/purpose se manual linking.

**Result:** agent linked. Automatic listing permission ka fix verify nahi hua. Listing chahiye to administrator relevant ACL/API policy correct kare aur Load agents retry kare.

## Error 3. Protected original - read-only aur Add tool disabled

**Messages:** record IT Service Management AI agent collection application mein hai, current scope Global hai; record has a protection policy.

**Meaning:** original editor se modify nahi ho sakta tha. Scope switch alone protection hatane ka confirmed solution nahi.

**Action used:** user ne **Incident context AI agent (Copy)** duplicate banaya; editable fields/Add tool enabled verify kiya; copy ki own identity Signet mein link/approve ki.

**Correction to earlier selection:** original suggest karte waqt editability check nahi hui thi. Naye setup mein Part B Step 4 pehle check karo.

Description ka read-only instruction aur editor protection policy alag cheezein hain. Original/copy ka same name ya purpose same identity nahi banata.

## Error 4. Review and approval / Tools it may call nahi mil raha

**Meaning:** Connections page aur next review/setup form confuse ho rahe the.

**Resolution:** linked agent card ka **Review and approval** button dabao; next form mein Tools it may call tak scroll karo.

**Action names:** saved ServiceNow connection -> **Discovered tools** ke technical name copy karo. Action field manual hai; Add a registered tool dropdown alag hai.

## Error 5. RB-INV-17 - restricted special-category data

```text
RB-INV-17 only T1/T2 seals may allow Restricted tags (special_category)
```

**Meaning:** selected tier aur allowed special-category data incompatible the. Ye action-name error nahi tha.

**Correction advised for this test:** special-category data required nahi ho to **Data it may send to the model** mein special category uncheck; **Data that must never be sent** mein checked rakho; save/review complete karo.

Required ho to legitimate data requirement aur allowed tier/review align karo. Sirf validation bypass karne ke liye tier change mat karo. Later screenshot copy ke Gateway setup tak pahunchta hai; exact field-change screenshot separately supplied nahi hua.

## Error 6. Third-party agent needs a connection or company tool

Earlier related setup notes mein validation tha ki third-party agent ko mapped REST connection ya at least one company tool chahiye.

**Resolution for this MCP setup:** registered gateway tool aur required exact actions select karke save/approve karo. Ye current final summarization run ka error nahi tha.

## Error 7. OAuth tokens not available / expire soon

**Old credential flow:** credential save hone ke baad token absent tha. **Get OAuth Token** request ke baad stored-token expiry banner aaya.

**Direct Navin flow:** **OAuth Access or Refresh tokens are not available** banner aur Authenticate button aaye. Callback registration aur Signet consent ke baad warning hati; Re-authenticate button dikhne laga.

**Expiry handling:** fresh token/renewal ka result check karo. Purani screenshot ki expiry current token validity ka proof nahi. Fresh issue par past expiry dikhe to response lifetime aur instance/display timezone inspect karo; clock problem assume mat karo.

Token alone correct identity aur real tool call ka proof nahi hai.

## Error 8. MCP server not available yet - Control Tower sync pending

```text
MCP server not available yet
This MCP server is still being synced to AI Control Tower.
```

**Action:** kuch minutes baad refresh/retry. Later View approval record se gateway asset successfully open hua.

**Result:** AI steward review se review workflow aur later Deployed screenshot mila.

**Cause limit:** exact elapsed time, sync root cause ya scheduled job fix establish nahi hua. Earlier Perimetra investigation ki missing-CI warning is incident server ka confirmed cause nahi hai. OAuth recreation, shipped-script modification ya fake CI insertion is setup ka demonstrated fix nahi tha.

Persistent ho to AI steward/admin exact server/connection ki sync status aur related logs inspect kare.

## Error 9. AICT No data, wrong list ya pending lifecycle

**Observed:** Unmanaged MCP list empty thi; filter changes par copy-related records dikhe. Role/instructions records bhi similar name se the.

**Correction:** intended asset class, Managed/Unmanaged list, filters aur actual record identity verify karo. Sirf naam ya list title se record type decide mat karo.

**Navigation:** Lifecycle tab mein review/tasks milte hain; Related Variants mein connection references. Empty onboarding tasks completed review ka proof nahi.

**Result:** copied agent ka Managed/Deployed detail screenshot mila. Ye gateway execution evidence nahi hai.

## Error 10. There are no tools from this MCP server

**Observed:** old **Signet Incident Gateway** select karne par Select tool disabled aur no-tools error tha.

**Checked:** full HTTP Connection URL, credential attachment, Active status, Token URL aur Client Credentials settings. Current festive hostname user ne confirm kiya. Gateway/copy ke AICT deployment ke baad bhi old flow mein error raha.

**Diagnostics attempted:** ngrok inspector aur F12 Network requests. Supplied captures mein dashboard requests aur ServiceNow exec/batch rows the; actual discovery response body/root cause nahi mila. Dashboard ka HTTP 200 MCP success nahi hai.

**Working outcome:** **Navin + OAuth 2.1 Manual Registration + Authorization Code + callback registration + Authenticate/consent** path par tools load hue; incident summary test successful hua.

**What remains unknown:** old Client Credentials path ka exact failure cause establish nahi hua. AICT approval ya Name/Description fill karna verified fix nahi tha.

Repeat ho to:

1. Correct client identity, current hostname, full MCP URL aur registered route verify karo.
2. F12 -> Network -> Fetch/XHR clear karke MCP server selection trigger karo.
3. Relevant exec/batch Payload aur Response inspect karo; HTTP 200 alone enough nahi.
4. Ngrok **http://127.0.0.1:4040** -> Clear Requests, same selection trigger, actual `/v1/mcp/servicenow-incidents` status/body inspect karo.
5. Request na aaye to ServiceNow backend/cached tool-list path inspect karo; external request failure assume mat karo.
6. Cookies, Authorization headers aur tokens share mat karo.

## Error 11. Authorization URL required; endpoint implemented nahi tha

**Observed:** ServiceNow direct OAuth form Authorization URL maang raha tha; Signet pehle workload Client Credentials flow support karta tha.

**Implementation:** browser login/consent, exact callback registration, mandatory S256 PKCE, five-minute single-use code, confidential client authentication aur rotating refresh tokens add hue. UI current Hosted Signet control address se dynamic Authorization/Token URLs dikhata hai.

**Result:** ServiceNow request S256 ke saath aayi; callback fix ke baad authentication, tool discovery aur test successful hue. Dummy Authorization URL nahi use ki gayi.

Capabilities: `<PUBLIC_SIGNET_URL>/api/v1/identity/oauth-metadata`. Dynamic Client Registration implement nahi hai; Manual Registration use karo.

## Error 12. API_RESPONSE_FORMAT - callback settings API returned 404 HTML

**Observed:** new callback API se JSON ke badle HTTP 404 text/html aaya.

**Checked:** source mein new route tha; running local/public control ne new metadata route ko old authenticated API jaisa treat kiya. Frontend updated tha, running backend old version tha.

**Resolution:** control/dev process restart. Session mein port 4100 process stop aur closed state verify ki gayi. Updated source next start par load hota hai.

Normal restart:

1. Running `npm run dev` terminal mein Ctrl+C.
2. Root se `npm run dev` dobara.
3. Services ready hone par browser Ctrl+Shift+R.
4. Ngrok current web port/address se running rakho.

Credentials regenerate karna old backend ka fix nahi hai.

## Error 13. Register this client callback URL before authorizing

```text
HTTP 400
Register this client callback URL in Gateway setup before authorizing
```

**Meaning:** Authenticate request wale Client ID ka callback Signet mein registered nahi tha.

**Actual request:** `redirect_uri` ServiceNow `/oauth_redirect.do` tha; `code_challenge_method=S256` present tha.

**Resolution:** same copy Client ID ke Gateway setup -> OAuth Authorization Code mein exact callback save kiya (Part B Step 9), phir **Navin -> Authenticate** se fresh flow start kiya.

**Result:** warning hati aur Re-authenticate button aaya. Error page ka old URL refresh karna fresh Authenticate ka replacement nahi.

## Error 14. Hostname / alias confusion

**Observed:** ek screenshot mein `another-unplanned-throwing.ngrok-free.dev` aur `mcp://signet-demo` tha. Baad mein festive hostname confirm hua; actual connections mein festive URL aur `servicenow-incidents` verify hua.

**Resolution:** current configured origin aur actual registered route use karo. Unverified alias ko same incident upstream assume mat karo. ServiceNow upstream URL aur Signet outbound gateway URL interchange mat karo.

## Error 15. Earlier runtime outage - HTML instead of JSON

Earlier project notes mein PostgreSQL-era `ECONNRESET` ke baad control/local service group stop hua aur ngrok ne HTTP 502 HTML diya. Frontend ne `Unexpected token '<'` show kiya.

**Recorded resolution:** dev services restart ke baad `/healthz` HTTP 200 JSON aur protected API JSON response restored. API helper non-JSON status/content type clearly report karta hai.

**Current distinction:** repository ab MongoDB use karti hai. Ye historical outage diagnosis hai; current 404/future outage ko bina logs same database issue mat bolo. Current process, database/network aur tunnel logs inspect karo.

# Part E - Final verification checklist

- [ ] Current public origin saved callback, Hosted Signet, Authorization/Token aur MCP URLs mein aligned hai.
- [ ] ServiceNow upstream connection Authorized; exact incident tools discovered hain.
- [ ] Editable copy ka actual sys_id linked hai.
- [ ] Correct gateway alias aur actions intended agent/environment ke liye approved hain.
- [ ] Client ID/Secret copy ke hain.
- [ ] Same client ka actual outbound callback Signet mein registered hai.
- [ ] Navin Authenticate aur Signet consent complete hain.
- [ ] Applicable AICT reviews correct assets par complete hain.
- [ ] Navin MCP tool copy mein attached aur correct saved active version selected hai.
- [ ] Real incident test expected tool aur result deta hai.
- [ ] Same call correct agent/action/route se Signet Activity mein verified hai.
- [ ] Execution-history monitoring required ho to separate source/sync verified hai.

Implementation validation mein typecheck/build aur real isolated-MongoDB HTTP integration tests login/consent, callback binding, PKCE, code expiry/replay, refresh rotation, revocation aur existing connection flows cover karte hain. Ye live Signet evidence ka replacement nahi. Is documentation update ne application configuration change ya connection test rerun nahi kiya.
