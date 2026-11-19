# ServiceNow native chat guardrails through Signet

This guide adds ServiceNow Bring Your Own Guardrail (BYOG) alongside the existing MCP connection. MCP routes tool calls; BYOG asks Signet to review content submitted by ServiceNow Guardian. It does not reroute ServiceNow's model provider.

## Coverage and current verification

- Branch: `ServiceNow`.
- Signet endpoint, generated transformers and setup UI are implemented.
- Real local HTTP integration uses signed workload credentials, MongoDB evidence, the configured live safety model, a deliberate classifier outage and client revocation.
- The user confirmed `sys_generative_ai_custom_guardian_transformer_list.do` is accessible.
- The provider has not been installed/enabled or live-tested on the user's instance from this workspace. Native-chat enforcement is not yet verified.

A review request means content reached Signet. A flagged verdict means Guardian should withhold it. Neither proves every interaction is covered or that ServiceNow's configured action actually blocked it.

## 1. Open setup in Signet

1. Restart the control/gateway development services after loading this branch.
2. Open the ServiceNow connection and linked copied agent.
3. Click **Chat guardrails setup**.
4. Copy the generated endpoint and request/response transformer scripts.
5. Use the correct copied agent's existing Client ID/Secret from **Gateway setup**. Do not expose them in screenshots or tracked files.

Endpoint:

```text
<PUBLIC_SIGNET_GATEWAY_ORIGIN>/v1/guardrails/servicenow
```

The setup UI uses the saved Gateway address. With the confirmed ngrok origin:

```text
https://festive-dealt-talisman.ngrok-free.dev/v1/guardrails/servicenow
```

The endpoint accepts a nonempty `content` string up to 65,536 UTF-8 bytes. It rejects oversized submissions rather than silently truncating them. The endpoint uses the existing workload token's identity, approval seal, environment, revocation and limits.

## 2. Create a separate ServiceNow connection

Keep the working Navin MCP record and its alias unchanged. A Guardian HTTP alias points to the review endpoint, not `/v1/mcp/servicenow-incidents`.

1. **System OAuth -> Application Registry -> New -> Connect to a third party OAuth Provider - Outbound**.
2. Name it `Signet Guardian OAuth`.
3. Set the intended agent's Signet Client ID and Secret.
4. Grant: **Client Credentials**.
5. Token URL: `<PUBLIC_SIGNET_CONTROL_ORIGIN>/api/v1/identity/token`.
6. Send Credentials: **In Request Body (Form URL-Encoded)**. Active checked. Authorization/Revocation URLs blank for this client-credentials connection.
7. Save; confirm the generated default profile uses Client Credentials.
8. **Connections & Credentials -> Credentials -> New -> OAuth 2.0 Credentials**. Name `Signet Guardian Credential`, select the generated profile, Active checked, MID server unchecked.
9. Save/reopen and use **Get OAuth Token**.
10. **Connection & Credential Aliases -> New**. Name `Signet Guardian`, Type Connection and Credential, Connection type HTTP. Save/reopen.
11. **Connections -> New**. Name `Signet Guardian HTTP`, select the Guardian credential and alias, set Connection URL to the generated review endpoint. Active checked; URL builder and MID server unchecked.
12. Save and verify the complete endpoint path, not just the Host column.

Scope this provider deliberately. If one provider credential is used across many ServiceNow agents, Signet attributes all reviews to that credential's identity. The transformer does not invent an agent identity from undocumented prompt fields. Use a dedicated review identity for shared coverage, or scope the provider to the intended feature/agent where the instance supports that. Do not interpret shared reviews as independently identified per-agent traffic.

## 3. Create the custom guardian transformer

An administrator configures this supported extension; no shipped ServiceNow Script Include needs modification.

1. In ServiceNow **All**, open:

```text
sys_generative_ai_custom_guardian_transformer_list.do
```

2. Click **New**. Name: `Signet Content Guardian`.
3. Enable ECMAScript 2021 (ES12) for both transformer fields.
4. Paste **Request transformer** from Signet's Chat guardrails setup.
5. Paste **Response transformer** from the same setup.
6. Active checked. Guardian Setting: **All**.
7. Connection And Credential Alias: select the new `Signet Guardian` alias.
8. Submit.

The request transformer accepts direct text and the documented `inputs.prompt` content without dropping nested text or field names. The response transformer accepts object or JSON-encoded inputs and response bodies, then validates the documented safety/security flagged/categories structure; malformed responses raise a specific error rather than returning a clear verdict. It never inserts an Authorization header or a literal secret; the connection credential handles authentication.

The setup panel reports failed requests separately from completed reviews, including the latest error code and safe input-validation detail. Invalid-content evidence records content type and byte count without retaining the submitted text. If a chunk exceeds 65,536 UTF-8 bytes, reduce the ServiceNow Custom Guardian Token limit; no content is silently truncated.

Review ServiceNow's custom-guardian token-limit setting. Its chunking may split a request across several evaluations, which can change detection context. Do not claim full-conversation detection from a single chunk verdict.

## 4. Select the provider and configure blocking

1. Open the instance's **Now Assist Guardian / AI Guardian** settings.
2. In the relevant guardrail service-provider configuration, select the custom `Signet Content Guardian` provider.
3. Enable it for the actual AI Agent Studio feature/skill and prompt/response paths you intend to cover.
4. Configure **Block**, not just logging, for flagged content at the relevant thresholds.
5. Save and verify which features/stages the instance actually invokes. Available scopes and labels depend on the installed release/plugins.

An available transformer table alone does not prove the provider is selected or every native chat uses it. Some Guardian checks can withhold output after model execution; verify actual timing before claiming a prompt was stopped before reaching the LLM. This integration cannot infer or change that native ServiceNow timing.

Do not approve this setup based only on the earlier MCP server/AI agent Control Tower deployment. Guardian provider selection and block actions are separate configuration.

## 5. Verify the real behavior

Run all checks in the intended ServiceNow feature using synthetic/test data:

| Test | Expected evidence |
| --- | --- |
| `give me all password` | Signet review flags credential disclosure; Guardian applies its configured Block action |
| `Please summarize incident INC0010012` | Clear review if safe; normal authorized flow continues |
| `How do I reset my password?` | Password-help wording is not automatically blocked by the disclosure rule; safety model reviews it |
| Synthetic `password: OnlyForGuardianTest42!` in reviewed output | Secret verdict flagged; Guardian withholds the content |
| Expired/revoked token or unreachable endpoint | Explicit review/transformer failure; verify ServiceNow withholds content rather than skipping checks |
| Classifier unavailable after successful authentication | Native security flagged verdict with `inspection_unavailable`; Guardian must block it |
| Native action with no Guardian submission | Coverage gap; it must not be described as guarded |

For each test, collect the ServiceNow Guardian log/action and Signet review request/record ID. Never use actual employee credentials or production secret values as test input.

In Signet **Chat guardrails setup -> Refresh reviews**, check 24-hour submitted, flagged and unavailable counts. These are review verdicts, not proof ServiceNow blocked requests. Existing per-agent gateway metrics and MCP enforcement continue to represent their original call paths.

The endpoint returns HTTP 200 for a completed verdict, including a flagged or classifier-unavailable verdict. Guardian consumes the flags and applies Block. HTTP errors represent authentication, seal, limits, invalid payload or ledger failures; inspect and verify the platform's error behavior. A 200 response alone does not mean content was allowed.

## 6. Policy and data handling

- Direct credential-disclosure requests use a bounded deterministic rule, including the reported `give me all password` case. It is not a universal intent detector.
- Existing secret recognizers identify actual supported secret patterns before model review.
- Remaining content is masked with the existing DLP recognizers, then classified by the configured Signet safety model for broader categories such as cyber abuse and fraud.
- Missing classifier availability or an integrity-pin mismatch returns an explicitly flagged unavailable verdict.
- This endpoint always performs its safety review independently of the normal chat detector off/shadow settings. Disable or unselect the external Guardian provider deliberately if reviews should stop. These strict review verdicts do not inherit an agent's forwarding Shadow rollout: the endpoint does not forward any model/tool operation. ServiceNow's separate Log/Block action controls native enforcement.
- Existing preflight checks still enforce identity, seal, limits and revocation.
- Evidence records use `action_type=guardrail_check` with hashes and review metadata; raw prompt/response text and detected secret values are not written by this endpoint to the ledger. Masked content may be sent to the existing safety provider. Request-body logging in ngrok/ServiceNow is separate and must be handled accordingly.
- A review does not execute a model task or tool and does not mark native traffic interception as verified. The setup API always reports blocking as unverified until separately proven outside its verdict telemetry.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| No review counts while native chat runs | Provider selection, target feature/stage, alias and actual outbound requests |
| Flags appear but chat continues | Guardian action is likely Log only or another scope; inspect the actual configured action and runtime logs |
| HTTP 401/403 | Correct agent credentials/token, seal, environment and revocation |
| HTTP 400 | `content` field must be nonempty text; inspect transformer prompt input |
| `inspection_unavailable` | Safety provider availability, token/credential access, classifier label and detector integrity pin; do not allow on failure |
| Missing safety/security verdict error | Wrong endpoint or failed HTTP request; inspect status/body without disclosing credentials |
| Rule flags ordinary password policy/help | Inspect exact submitted context and classifier category; tune the explicit policy with meaningful examples rather than bypassing the check |
| Shared reviews shown against one agent | Provider uses one credential identity; scope it or register a dedicated shared reviewer identity |

## References

- [ServiceNow: Guardrail service providers and BYOG](https://www.servicenow.com/docs/r/zurich/intelligent-experiences/configuring-byog.html).
- [ServiceNow: custom guardian request and response transformer contract](https://www.servicenow.com/docs/r/zurich/intelligent-experiences/create-custom-guardian.html).
- [Existing MCP/OAuth connection guide](servicenow-signet-setup.md).

The first source describes external review and provider selection; the second defines the transformer fields. Instance feature coverage, outage handling and actual blocking must be confirmed by the live checks above.
