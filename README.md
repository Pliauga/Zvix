# Zvix: LLM Security & Data Loss Prevention Proxy

Zvix is a lightweight security proxy and DLP inspection layer for LLM inference workloads. It runs inline on
AWS Lambda + API Gateway (emulated locally via Floci) in front of an Ollama inference backend, intercepting
prompt injections and sensitive data leakage before the prompt leaves the trust boundary and again before the
completion reaches the client.

---

## Architecture

```
[ Client Application ]  -- Authorization: Bearer <ZVIX_API_TOKEN>
         |
         | POST /v1/chat
         v
[ API Gateway v2 (HTTP API) ]  -- REQUEST authorizer (10s timeout), route throttling 20 burst / 10 rps
         |
         v
[ Zvix Lambda Handler ]  -- 30s timeout, 20s internal upstream budget
    0. Authorize    -> constant-time bearer comparison (401 when the shared secret is missing or wrong)
    1. Ingress Scan -> payload size cap (413), credential DLP and injection heuristics (403)
    2. Model Proxy  -> dispatch prompt to Ollama over the compose network (http://ollama:11434)
    3. Egress Scan  -> audit the completion for secret exfiltration (403 OUTPUT_DLP_VIOLATION)
    4. Client Return-> deliver the inspected completion (200 OK) with a request id
         |
         v
[ Ollama Inference Engine ]  -- llama3.2:1b, no published host port
```

---

## Core Design Decisions

- **Deterministic scanners over LLM-as-a-judge**: every request is classified by compiled regular expressions plus
  Luhn and Shannon-entropy validators, so inspection cost is linear in payload size and independent of model load.
- **Fail-closed security posture**: transport failures, malformed payloads, inspection errors and budget exhaustion
  return 5xx responses that carry only `error_code`, `message` and `request_id`; uninspected content is never
  forwarded and the matched rule is never disclosed to the caller.
- **Zero-dependency runtime**: the Lambda artifact uses only the Python standard library (`re`, `json`, `urllib`,
  `hmac`, `unicodedata`), so `src/requirements.txt` stays empty and cold starts stay minimal.
- **Bounded work per request**: ingress is capped at `MAX_INPUT_BYTES` (32768) before decoding, upstream bodies at
  `MAX_OUTPUT_BYTES` (65536), generation at `MAX_GENERATE_TOKENS` (32), decoding recurses at most
  `MAX_DECODE_DEPTH` (3) layers, and all upstream attempts share one monotonic 20s deadline below the 30s
  Lambda timeout.
- **Hermetic local emulation**: Floci runs containerized Lambda functions against the host Docker daemon alongside
  Ollama, so the full integration path is exercised at zero cloud cost.

---

## Security Controls

| Layer | Control | Behaviour |
| --- | --- | --- |
| Transport | Bearer shared secret | `401 UNAUTHORIZED` before any upstream call when `ZVIX_API_TOKEN` is set |
| Transport | Payload cap | `413 PAYLOAD_TOO_LARGE` above `MAX_INPUT_BYTES`, checked before base64/JSON decoding |
| Ingress | Credential DLP | AWS, Anthropic, OpenAI, GitHub, Slack, Google, PEM blocks, JWTs, bearer tokens, PAN (Luhn + BIN), UK NI |
| Ingress | Injection heuristics | instruction override, system-prompt extraction, jailbreak personas, delimiter injection |
| Ingress | Canonicalisation | NFKC, format-character stripping, whitespace folding and bounded base64/percent/hex decoding |
| Upstream | Budget | one deadline for every attempt, `504 UPSTREAM_TIMEOUT` past the budget |
| Upstream | Response cap | `502 UPSTREAM_RESPONSE_TOO_LARGE` when the body exceeds `MAX_OUTPUT_BYTES` |
| Egress | Output DLP | `403 OUTPUT_DLP_VIOLATION`, credentials never leave the boundary |
| Observability | Structured logs | timestamp, request id, stage, decision, violation type, rule, latency, payload hash prefix |

The formal arguments behind these controls, including the false-positive and false-negative bounds, live in
[mathematical_proofs.md](mathematical_proofs.md).

---

## Quickstart

### Prerequisites

- Docker & Docker Compose
- Python 3.11+
- AWS CLI (`aws`)

### 1. Start local infrastructure

```bash
docker compose up -d --wait
```

The emulator publishes `127.0.0.1:4566`; set `FLOCI_PORT` when 4566 is already taken, for example
`FLOCI_PORT=4577 docker compose up -d --wait` together with `FLOCI_URL=http://localhost:4577 ./scripts/deploy.sh`.

### 2. Deploy the proxy, authorizer and API

```bash
export ZVIX_API_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
./scripts/deploy.sh
```

The script refuses to run without `ZVIX_API_TOKEN`, attaches the Lambda basic-execution policy so CloudWatch logs
are readable, applies route throttling, and prints the captured gateway endpoint. On emulators without API Gateway
authorizer or throttling support it prints a warning instead of failing; the bearer check still runs inside the
proxy Lambda before any upstream call.

### 3. Run verification

```bash
# in-process handler, no network required
python3 scripts/test_attacks.py --mode direct

# deployed endpoint
python3 scripts/test_attacks.py --mode http --endpoint "$GATEWAY_URL"
```

The suite takes `--mode {direct,http}` and defaults to `direct`; it prints the selected mode and target, and the
direct mode forces mock completions regardless of the ambient `MOCK_LLM_MODE`. The egress interception vector
runs in both modes through the `__zvix_canary__` prompt and `ZVIX_CANARY_RESPONSE` canary.

---

## Image pinning

Both services are referenced by version tag, and every image should additionally be pinned by digest. The Floci
image is pinned to the digest resolved on the development host:

```text
floci/floci:2.4.0
sha256:5ee85db604c4aa74ac76e07ea5cc83086f37bb472bf3dbb97e34019e48efae9c
```

The Ollama image is pinned to the digest of the multi-architecture index resolved with
`docker buildx imagetools inspect ollama/ollama:0.5.4`:

```text
ollama/ollama:0.5.4
sha256:18bfb1d605604fd53dcad20d0556df4c781e560ebebcd923454d627c994a0e37
```

---

## Residual risks

- `/var/run/docker.sock` is mounted into Floci so the containerized Lambda executor can start sibling containers;
  that grants the emulator root-equivalent host access and must stay limited to local development.
- Ollama stays on the compose bridge network without a published host port, but it still needs outbound access
  once to pull the model. Set the network to `internal: true` after the model is cached if egress must be blocked.
- The shared bearer secret is stored in the Lambda environment for the emulator only; production deployments should
  source it from a secret manager and rotate it.
- Prompt evaluation is CPU-bound on the emulator host, so a prompt close to the 32KB transport cap can exceed the
  20s upstream budget and return `504 UPSTREAM_TIMEOUT`; size the budget to the inference host in production.

---

## License

MIT
