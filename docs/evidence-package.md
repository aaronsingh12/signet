# Signet Evidence Package (`.sep`), format `signet-evidence-package/1`

An Evidence Package lets an auditor verify Signet evidence offline, without trusting TechSnitch or the
tenant's administrators (Blueprint 1B.2). It is produced by `GET /api/v1/ledger/export` and checked by
`signet-verify`.

## Container

A gzip stream of UTF-8 newline-delimited JSON. Every line is one object with a `type` field. Lines appear
in this order:

| Line | `type` | Content |
| --- | --- | --- |
| 1 | `manifest` | `format`, `tenant`, `tenant_name`, `created_at`, `created_by`, `range` (`from_day`, `to_day`, `from_seq`, `to_seq`), `record_count`, `start_prev_hash` (the `prev_hash` of the first record), `keys.ledger` and `keys.ca` (public JWKs), `payloads_included` |
| 2..n | `root` | `day`, `jws`: a signed daily root (below) for each finished UTC day in range |
| n+1.. | `record` | `record`: one ledger record, in sequence order |
| last | `end` | `sha256` of every preceding line (each including its trailing `\n`), and `signature`: a JWS (`typ: signet-sep`) by the ledger key over `{format, sha256, record_count, roots}` |

## Records

`record_hash = SHA-256(JCS(record without record_hash) || prev_hash)`, where JCS is RFC 8785 canonical JSON
and `||` is string concatenation of the hex `prev_hash`. The first record of a tenant has
`prev_hash = 0…0` (64 zeros). Sequence numbers are contiguous; a gap is a verification failure.

Records hold metadata only: data classes, counts, hashes of prompts, responses and arguments, rule IDs,
detector versions and scores, and latencies. Payload values are never in a package unless the tenant
grants it (`payloads_included`).

## Daily roots

Each finished UTC day is a Merkle tree (RFC 9162 hashing: leaf = SHA-256(0x00 ‖ record_hash bytes),
node = SHA-256(0x01 ‖ left ‖ right)) over that day's record hashes in sequence order. The root is a JWS
(`typ: signet-root`, EdDSA, ledger key) over:

```json
{ "format": "signet-daily-root/1", "tenant": "…", "day": "2026-10-28", "first_seq": 1, "last_seq": 4210,
  "count": 4210, "merkle_root": "<hex>", "chain_head": "<record_hash of last_seq>", "signed_at": "…" }
```

`chain_head` ties the root to the hash chain, so a root cannot be moved to a different history.
Roots and the day's records are also written once to write-once storage (S3 Object Lock in production).

## Verification (what `signet-verify` checks)

1. The ledger key fingerprint, optionally against a key the auditor obtained independently (`--key`).
2. The end-line signature, and that the SHA-256 of the package lines matches it.
3. The hash chain from `start_prev_hash` through every record, with contiguous sequence numbers.
4. For each root: the signature, that the package holds exactly `count` records for that day, that the
   Merkle root recomputed from them matches, and that `chain_head` matches the last record.

Any single changed byte in a record fails steps 2 and 3 and is reported with the record's sequence number.
