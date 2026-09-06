# Zvix: LLM Security & Data Loss Prevention Proxy

Zvix is a lightweight security proxy and DLP inspection layer for LLM inference workloads. It runs inline on AWS Lambda + API Gateway (emulated locally via Floci) in front of an Ollama inference backend, intercepting prompt injections and sensitive data leakage with sub-millisecond overhead.

---

## Architecture

The proxy inspects incoming prompts and outgoing model completions:

```
[ Client Application ]
         |
         | POST /v1/chat
         v
[ API Gateway v2 (HTTP API) ]
         |
         v
[ Zvix Lambda Handler ]
    1. Ingress Scan  -> Check for credential leaks / injection heuristics (403 if matched)
    2. Model Proxy   -> Dispatch prompt to Ollama upstream (http://ollama:11434)
    3. Egress Scan   -> Audit model output for secret exfiltration (403 if matched)
    4. Client Return -> Deliver sanitized completion (200 OK)
         |
         v
[ Ollama Inference Engine ]
    (llama3.2:1b)
```

---

## Core Design Decisions

- **Pre-compiled Regex over LLM-as-a-Judge**: Evaluates pattern signatures in under 1ms per request, avoiding token costs and the 500ms–2000ms latency overhead of secondary LLM verification.
- **Fail-Closed Security Posture**: Transport errors, malformed payloads, or inspection crashes return HTTP 500 (`INTERNAL_SECURITY_PROXY_ERROR`), ensuring uninspected traffic is never passed downstream.
- **Zero-Dependency Runtime**: The core Lambda function uses only Python standard library modules (`urllib`, `re`, `json`), keeping the deployment artifact under 10KB and cold starts minimal.
- **Hermetic Local Emulation**: Floci executes containerized Lambda functions locally against the host Docker daemon alongside Ollama, enabling full integration tests at zero cloud cost.

---

## Quickstart

### Prerequisites
- Docker & Docker Compose
- Python 3.11+
- AWS CLI (`aws`)

### 1. Start Local Infrastructure
```bash
docker compose up -d
```

### 2. Deploy Lambda & API Gateway
```bash
./scripts/deploy.sh
```

### 3. Run Verification Tests
```bash
python3 scripts/test_attacks.py
```

To run against a live deployed API Gateway URL:
```bash
python3 scripts/test_attacks.py --endpoint http://localhost:4566/_aws/http-api/<API_ID>/v1/chat
```

---

## License
MIT

