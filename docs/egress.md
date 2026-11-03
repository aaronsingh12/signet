# Keeping agents behind the gateway (egress)

Signet governs the calls that reach its gateway. An agent that still holds a provider key and has open
internet access can call the provider directly, and Signet would not see it. Two things close that gap,
and they are different in kind:

| | What it does | Who enforces it |
| --- | --- | --- |
| **Keyless runtime** | The agent holds no model or tool credentials; it has only a workload identity. A direct call has nothing to authenticate with. | Signet (Secrets Broker, workload identity) |
| **Bypass detection** | At start-up the SDK reports provider-key variable names and provider URLs it finds in the runtime, and optionally whether a direct connection to a provider succeeds. Reports appear on the agent's Connection tab and as Discovery findings marked *detected, not enforced*. Uploaded network logs show direct traffic to AI providers from other hosts. | Signet detects; it does not block |
| **Egress restriction** | The network lets the agent reach only the gateway (and DNS). | Your infrastructure. **Signet does not enforce network egress** |

Signet never reports a network restriction as enforced: it cannot see your firewall.

## Remove direct credentials

- Delete `OPENAI_API_KEY`, `OLLAMA_API_KEY`, `ANTHROPIC_API_KEY` and similar from the agent's
  environment, image, secrets store and repository. Run `npm run keysweep -- <dir> --upload` over the
  repository; findings close automatically once the same key is in the Secrets Broker.
- Rotate any key that was ever in the agent's runtime.

## Restrict outbound traffic

Allow the agent to reach only the Signet gateway (TCP 443, or the gateway port) and DNS. Also allow the
control plane if the agent exchanges its own credentials (the SDK does). Everything else is denied.

**Docker / Compose**: put the agent on an internal network that has no route out; only the gateway (or
the sidecar) is attached to both networks.

```yaml
networks:
  agent-net: { internal: true }   # no outbound internet
  edge: {}
services:
  agent:   { networks: [agent-net] }
  sidecar: { image: signet/sidecar, networks: [agent-net, edge], environment: [SIGNET_SIDECAR_BIND=0.0.0.0, ...] }
```

**AWS (EC2, ECS, EKS)**: security group egress rule only to the gateway's address or prefix list on
443; no NAT gateway route for the agent's subnet; VPC endpoints for AWS services it needs. If the
gateway runs in the same VPC, reference its security group.

**Kubernetes**: a default-deny egress NetworkPolicy for the agent's namespace, plus an allow rule to
the gateway service and kube-dns. Use a CNI that enforces NetworkPolicy.

**Azure / GCP VMs**: NSG / VPC firewall egress rules as for AWS.

**RunPod**: pods have open outbound internet and RunPod offers no egress firewall. On RunPod Signet
can make the agent keyless and *detect* a bypass, but cannot have it *prevented*. For enforcement, run
the agent where you control egress (a VPC provider, or behind your own proxy with a WireGuard tunnel
that is the pod's only route, which you configure and maintain).

**Self-hosted servers**: host firewall (nftables/iptables, Windows Firewall) allowing outbound only to
the gateway, or a forward proxy that allows only the gateway host.

## Check it

1. Start the agent with the SDK (`SIGNET_EGRESS_CHECK=1`, the default). Its Connection tab should
   show *no bypass found*: no provider variables, and direct connections to providers failing.
2. From inside the runtime: `curl -m 5 https://api.openai.com` should fail; `curl $SIGNET_GATEWAY_URL/healthz` should work.
3. Upload proxy or firewall logs to *Discovery → Upload network logs* now and then. Direct traffic to
   AI providers from hosts other than the gateway's egress addresses becomes a finding.
