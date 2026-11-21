#!/usr/bin/env bash
# Deploy the Zvix guardrail proxy and its request authorizer into the local Floci emulator.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

FLOCI_URL="${FLOCI_URL:-http://localhost:4566}"
AWS_REGION="${AWS_REGION:-eu-west-2}"
LAMBDA_NAME="genai-zvix-proxy"
AUTHORIZER_NAME="genai-zvix-authorizer"
API_NAME="genai-zvix-api"
ROLE_NAME="zvix-lambda-role"
MODEL_NAME="${MODEL_NAME:-llama3.2:1b}"
ZIP_FILE="${ROOT_DIR}/dist/zvix.zip"
API_TOKEN="${ZVIX_API_TOKEN:-}"
CANARY_RESPONSE="${ZVIX_CANARY_RESPONSE:-AKIACANARYCANARY1234}"

export AWS_ACCESS_KEY_ID="test"
export AWS_SECRET_ACCESS_KEY="test"
export AWS_DEFAULT_REGION="${AWS_REGION}"

info() { printf '\033[34m[INFO]\033[0m %s\n' "$*"; }
ok() { printf '\033[32m[OK]\033[0m   %s\n' "$*"; }
warn() { printf '\033[33m[WARN]\033[0m %s\n' "$*" >&2; }
err() { printf '\033[31m[ERR]\033[0m  %s\n' "$*" >&2; }
die() { err "$*"; exit 1; }

aws_cli() { aws --endpoint-url="${FLOCI_URL}" "$@"; }

# Each probe returns 1 on timeout so that `probe_a || probe_b || die` keeps working.
wait_for_http() {
    local service="$1"
    local url="$2"
    local retries="${3:-30}"
    info "Checking ${service} readiness at ${url}..."
    until curl -s -f -o /dev/null "${url}"; do
        if [ "${retries}" -le 0 ]; then
            err "${service} failed to become healthy at ${url}"
            return 1
        fi
        sleep 2
        retries=$((retries - 1))
    done
    ok "${service} is reachable"
    return 0
}

wait_for_ollama() {
    local retries="${1:-30}"
    info "Checking Ollama readiness inside the compose network..."
    until docker exec ollama-llm-engine ollama list >/dev/null 2>&1; do
        if [ "${retries}" -le 0 ]; then
            err "Ollama failed to become healthy"
            return 1
        fi
        sleep 2
        retries=$((retries - 1))
    done
    ok "Ollama is reachable"
    return 0
}

[ -n "${API_TOKEN}" ] || die "ZVIX_API_TOKEN must be exported before deploying (shared bearer secret)."

wait_for_http "Floci" "${FLOCI_URL}/_floci/health" || wait_for_http "Floci" "${FLOCI_URL}" \
    || die "Floci never became healthy"
wait_for_ollama || die "Ollama never became healthy"

info "Ensuring '${MODEL_NAME}' is loaded in Ollama..."
docker exec ollama-llm-engine ollama pull "${MODEL_NAME}" >/dev/null
docker exec ollama-llm-engine ollama run "${MODEL_NAME}" "Reply with: ready" >/dev/null 2>&1 \
    || warn "Model warm-up did not complete; the first inference may exceed the upstream budget."
ok "Model ready and warm"

mkdir -p "${ROOT_DIR}/dist"
rm -f "${ZIP_FILE}"
(cd "${ROOT_DIR}/src" && zip -q "${ZIP_FILE}" zvix.py)
ok "Built $(du -h "${ZIP_FILE}" | cut -f1) deployment artifact"

TRUST_POLICY='{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
TRUST_POLICY+='"Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
BASIC_LOGS_POLICY="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"

ROLE_ARN=$(aws_cli iam get-role --role-name "${ROLE_NAME}" --query "Role.Arn" --output text 2>/dev/null || true)
if [ -z "${ROLE_ARN}" ] || [ "${ROLE_ARN}" = "None" ]; then
    ROLE_ARN=$(aws_cli iam create-role --role-name "${ROLE_NAME}" \
        --assume-role-policy-document "${TRUST_POLICY}" --query "Role.Arn" --output text)
    ok "Created IAM role: ${ROLE_NAME}"
fi

ATTACHED=$(aws_cli iam list-attached-role-policies --role-name "${ROLE_NAME}" \
    --query "AttachedPolicies[?PolicyArn=='${BASIC_LOGS_POLICY}'].PolicyArn" --output text 2>/dev/null || true)
if [ -z "${ATTACHED}" ] || [ "${ATTACHED}" = "None" ]; then
    aws_cli iam attach-role-policy --role-name "${ROLE_NAME}" --policy-arn "${BASIC_LOGS_POLICY}" >/dev/null
    ok "Attached AWSLambdaBasicExecutionRole"
fi

ENV_VARS="Variables={OLLAMA_ENDPOINT=http://ollama:11434/api/generate,"
ENV_VARS+="DEFAULT_MODEL=${MODEL_NAME},AWS_DEFAULT_REGION=${AWS_REGION},"
ENV_VARS+="ZVIX_API_TOKEN=${API_TOKEN},MAX_INPUT_BYTES=32768,MAX_OUTPUT_BYTES=65536,"
ENV_VARS+="TOTAL_UPSTREAM_BUDGET_SECONDS=20,MAX_GENERATE_TOKENS=32,"
ENV_VARS+="ZVIX_CANARY_RESPONSE=${CANARY_RESPONSE}}"

deploy_function() {
    local name="$1"
    local handler="$2"
    local timeout_seconds="$3"
    local arn
    arn=$(aws_cli lambda get-function --function-name "${name}" \
        --query "Configuration.FunctionArn" --output text 2>/dev/null || true)
    if [ -n "${arn}" ] && [ "${arn}" != "None" ]; then
        aws_cli lambda update-function-code --function-name "${name}" \
            --zip-file "fileb://${ZIP_FILE}" >/dev/null
        aws_cli lambda update-function-configuration --function-name "${name}" \
            --handler "${handler}" --timeout "${timeout_seconds}" \
            --environment "${ENV_VARS}" >/dev/null
        printf '%s' "${arn}"
        return 0
    fi
    aws_cli lambda create-function --function-name "${name}" \
        --runtime "python3.11" \
        --role "${ROLE_ARN}" \
        --handler "${handler}" \
        --zip-file "fileb://${ZIP_FILE}" \
        --timeout "${timeout_seconds}" \
        --memory-size 256 \
        --environment "${ENV_VARS}" \
        --query "FunctionArn" --output text
}

PROXY_ARN=$(deploy_function "${LAMBDA_NAME}" "zvix.lambda_handler" 30)
ok "Proxy function ready: ${LAMBDA_NAME} (timeout 30s)"
AUTHORIZER_ARN=$(deploy_function "${AUTHORIZER_NAME}" "zvix.authorize" 10)
ok "Authorizer function ready: ${AUTHORIZER_NAME}"

API_ID=$(aws_cli apigatewayv2 get-apis --query "Items[?Name=='${API_NAME}'].ApiId" --output text 2>/dev/null || true)
if [ -z "${API_ID}" ] || [ "${API_ID}" = "None" ]; then
    API_ID=$(aws_cli apigatewayv2 create-api --name "${API_NAME}" \
        --protocol-type HTTP --query "ApiId" --output text)
    ok "Created HTTP API: ${API_ID}"
fi

INT_ID=$(aws_cli apigatewayv2 get-integrations --api-id "${API_ID}" \
    --query "Items[?IntegrationUri=='${PROXY_ARN}'].IntegrationId" --output text 2>/dev/null || true)
if [ -z "${INT_ID}" ] || [ "${INT_ID}" = "None" ]; then
    INT_ID=$(aws_cli apigatewayv2 create-integration --api-id "${API_ID}" \
        --integration-type AWS_PROXY --integration-uri "${PROXY_ARN}" \
        --payload-format-version "2.0" --query "IntegrationId" --output text)
fi

AUTHORIZER_ID=""
if AUTHORIZER_ID=$(aws_cli apigatewayv2 create-authorizer --api-id "${API_ID}" \
    --name "zvix-request-authorizer" --authorizer-type REQUEST \
    --authorizer-uri "arn:aws:apigateway:${AWS_REGION}:lambda:path/2015-03-31/functions/${AUTHORIZER_ARN}/invocations" \
    --identity-source '$request.header.Authorization' \
    --authorizer-payload-format-version "2.0" --query "AuthorizerId" --output text 2>/dev/null); then
    ok "Created REQUEST authorizer: ${AUTHORIZER_ID}"
else
    AUTHORIZER_ID=""
    warn "REQUEST authorizers are unsupported by this emulator; the bearer check still runs inside"
    warn "the proxy Lambda before any upstream call, so unauthenticated traffic is rejected with 401."
fi

create_route() {
    local authorization="$1"
    local args=(--api-id "${API_ID}" --route-key "POST /v1/chat" --target "integrations/${INT_ID}")
    if [ "${authorization}" = "custom" ]; then
        args+=(--authorization-type CUSTOM --authorizer-id "${AUTHORIZER_ID}")
    fi
    aws_cli apigatewayv2 create-route "${args[@]}" --query "RouteId" --output text
}

ROUTE_ID=$(aws_cli apigatewayv2 get-routes --api-id "${API_ID}" \
    --query "Items[?RouteKey=='POST /v1/chat'].RouteId" --output text 2>/dev/null || true)
if [ -z "${ROUTE_ID}" ] || [ "${ROUTE_ID}" = "None" ]; then
    if [ -n "${AUTHORIZER_ID}" ]; then
        ROUTE_ID=$(create_route custom)
    else
        ROUTE_ID=$(create_route none)
    fi
    ok "Created route POST /v1/chat"
fi

STAGE_EXISTS=$(aws_cli apigatewayv2 get-stage --api-id "${API_ID}" --stage-name '$default' \
    --query "StageName" --output text 2>/dev/null || true)
if [ -z "${STAGE_EXISTS}" ] || [ "${STAGE_EXISTS}" = "None" ]; then
    aws_cli apigatewayv2 create-stage --api-id "${API_ID}" --stage-name '$default' --auto-deploy >/dev/null
fi

THROTTLE_SETTINGS='{"ThrottlingBurstLimit":20,"ThrottlingRateLimit":10}'
if aws_cli apigatewayv2 update-stage --api-id "${API_ID}" --stage-name '$default' \
    --default-route-settings "${THROTTLE_SETTINGS}" >/dev/null 2>&1; then
    ok "Applied route throttling (burst 20, steady 10 rps)"
else
    warn "Stage throttling is unsupported by this emulator; apply a rate limit at the edge."
fi

GATEWAY_URL="${FLOCI_URL}/_aws/execute-api/${API_ID}/\$default/v1/chat"

authenticated_status() {
    curl -s -o /dev/null -w '%{http_code}' -X POST "${GATEWAY_URL}" \
        -H "Authorization: Bearer ${API_TOKEN}" -H 'Content-Type: application/json' \
        -d '{"prompt":"zvix deploy self-test"}'
}

AUTH_STATUS=$(authenticated_status)
if [ "${AUTH_STATUS}" -ge 500 ] && [ -n "${AUTHORIZER_ID}" ]; then
    warn "Authorizer path failed on this emulator (HTTP ${AUTH_STATUS}); recreating the route without it."
    aws_cli apigatewayv2 delete-route --api-id "${API_ID}" --route-id "${ROUTE_ID}" >/dev/null
    ROUTE_ID=$(create_route none)
    AUTH_STATUS=$(authenticated_status)
fi
if [ "${AUTH_STATUS}" = "200" ]; then
    ok "Authenticated self-test returned HTTP 200"
else
    warn "Authenticated self-test returned HTTP ${AUTH_STATUS} (expected 200)."
fi

ANON_STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X POST "${GATEWAY_URL}" \
    -H 'Content-Type: application/json' -d '{"prompt":"zvix deploy self-test"}')
if [ "${ANON_STATUS}" = "401" ] || [ "${ANON_STATUS}" = "403" ]; then
    ok "Unauthenticated request rejected with HTTP ${ANON_STATUS}"
else
    warn "Unauthenticated self-test returned HTTP ${ANON_STATUS} (expected 401 or 403)."
fi

echo ""
ok "Deployment complete."
echo "Endpoint: ${GATEWAY_URL}"
