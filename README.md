# Zvix

A security proxy that sits between a client and an LLM. It inspects the prompt before it reaches the model and the
completion before it reaches the client, then returns a decision with a request id.

The reference deployment is AWS Lambda + API Gateway in front of Ollama. `compose.yaml` runs the same code locally
through the Floci emulator, so the full request path can be exercised without an AWS account.

## Request path

```
client --POST /v1/chat, Authorization: Bearer <token>--> API Gateway --route--> proxy Lambda --HTTP--> Ollama
```

The proxy performs four steps in order:

1. Authorize: constant-time comparison against `ZVIX_API_TOKEN`; `401` when the token is missing or wrong.
2. Ingress scan: size cap, credential DLP, prompt-injection heuristics; `413` or `403`.
3. Forward: one POST to Ollama inside a shared deadline; `502`/`504` on upstream failure.
4. Egress scan: credential DLP on the completion; `403 OUTPUT_DLP_VIOLATION`.

Error bodies contain only `error_code`, `message` and `request_id`. The matched rule and the offending content are
never returned to the caller; they appear in the structured log line.

| Status | `error_code` | Cause |
| --- | --- | --- |
| 200 | - | inspected completion |
| 400 | `INVALID_JSON_PAYLOAD`, `INVALID_BASE64_PAYLOAD`, `MISSING_PROMPT` | malformed request |
| 401 | `UNAUTHORIZED` | missing or wrong bearer token |
| 403 | `DATA_LOSS_PREVENTION_VIOLATION`, `PROMPT_INJECTION_DETECTED`, `OUTPUT_DLP_VIOLATION` | policy violation |
| 413 | `PAYLOAD_TOO_LARGE` | body above `MAX_INPUT_BYTES` |
| 500 | `INTERNAL_SECURITY_PROXY_ERROR` | unexpected inspection failure |
| 502 | `UPSTREAM_RESPONSE_TOO_LARGE`, `UPSTREAM_LLM_UNAVAILABLE` | upstream body too large or unreachable |
| 504 | `UPSTREAM_TIMEOUT` | upstream budget exhausted |

## Layout

| Path | Purpose |
| --- | --- |
| `src/zvix.py` | proxy handler, scanners, upstream client, API Gateway authorizer |
| `scripts/deploy.sh` | builds `dist/zvix.zip`, deploys both Lambdas, creates the API and route, prints the endpoint |
| `scripts/test_attacks.py` | security suite, 37 vectors, `--mode {direct,http}` |
| `compose.yaml` | Floci emulator and Ollama on one bridge network |
| `src/requirements.txt` | empty: the runtime is standard library only |

## Run locally

Requires Docker, Docker Compose, Python 3.11+ and the AWS CLI.

```bash
export ZVIX_API_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
docker compose up -d --wait
./scripts/deploy.sh
```

`deploy.sh` refuses to run without `ZVIX_API_TOKEN`, pulls the model into the Ollama container, and prints the
gateway endpoint on the last line (`Endpoint: ...`).

If port 4566 is already in use, pick another one and point the deploy script at it:

```bash
export FLOCI_PORT=4577 FLOCI_URL=http://localhost:4577
docker compose up -d --wait && ./scripts/deploy.sh
```

Run the suite:

```bash
python3 scripts/test_attacks.py --mode direct             # in-process, mock completion, no network
python3 scripts/test_attacks.py --mode http -e "$GATEWAY_URL"
```

Set `ZVIX_API_TOKEN` when running the suite so the bearer vector is exercised instead of skipped. The two base64
transport vectors only run in direct mode, because the gateway cannot hand the handler a base64 event.

Tear down with `docker compose down --remove-orphans`.

## Configuration

All settings are read from the environment at start-up.

| Variable | Default | Effect |
| --- | --- | --- |
| `ZVIX_API_TOKEN` | unset | shared bearer secret; unset disables the check |
| `OLLAMA_ENDPOINT` | `http://ollama:11434/api/generate` | upstream generate URL |
| `OLLAMA_FALLBACK_ENDPOINT` | unset | second upstream tried when the first fails |
| `DEFAULT_MODEL` | `llama3.2:1b` | model field sent upstream |
| `TOTAL_UPSTREAM_BUDGET_SECONDS` | `20` | one deadline shared by every upstream attempt |
| `MAX_INPUT_BYTES` | `32768` | request body cap, enforced before decoding |
| `MAX_OUTPUT_BYTES` | `65536` | upstream response cap |
| `MAX_GENERATE_TOKENS` | `32` | `num_predict` sent to Ollama, bounds generation time |
| `MAX_DECODE_DEPTH` | `3` | layers of nested base64/percent/hex decoding |
| `MOCK_LLM_MODE` | unset | returns a canned completion instead of calling Ollama |
| `ZVIX_CANARY_RESPONSE` | unset | completion used for the `__zvix_canary__` prompt |

## Scanners

Ingress runs credential DLP and injection heuristics; egress runs credential DLP only.

- Credentials: AWS access keys, Anthropic, OpenAI and GitHub tokens, Slack tokens, Google API keys, PEM private
  keys, JWTs, bearer tokens, high-entropy assignments, payment card numbers (Luhn + issuer prefix), UK NI numbers.
- Injection: instruction override, system-prompt extraction, jailbreak personas, delimiter injection.
- Canonicalisation before matching: NFKC, format-character stripping, whitespace folding, and bounded decoding of
  base64, percent and hex runs.
- Compression is not decoded. A secret that only appears after gzip is not detected.

## Image pinning

Both images are pinned by tag and digest; the digests match `compose.yaml`.

```text
floci/floci:2.4.0
sha256:5ee85db604c4aa74ac76e07ea5cc83086f37bb472bf3dbb97e34019e48efae9c

ollama/ollama:0.5.4
sha256:18bfb1d605604fd53dcad20d0556df4c781e560ebebcd923454d627c994a0e37
```

Re-resolve them with `docker buildx imagetools inspect <image>:<tag>` before bumping either pin.

## CI

`.github/workflows/ci.yml` runs on push and pull request: `py_compile`, `flake8 src/ scripts/`, a 120-column check
on `scripts/*.sh`, the direct suite, then `docker compose up`, `deploy.sh`, the HTTP suite against the printed
endpoint, and teardown.

## Known limits

- The emulator needs `/var/run/docker.sock` to start Lambda containers, which is effectively host root. Local use
  only.
- Ollama needs outbound access once to pull the model; the port is not published, but the network is not `internal`.
- The bearer secret lives in the Lambda environment. Production should read it from a secret manager.
- Generation on the emulator host is CPU-bound (roughly 4 tokens/second), so a large prompt can exhaust the 20s
  budget and return `504`. The transport cap is enforced regardless.

## License

MIT
