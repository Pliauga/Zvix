#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

FLOCI_URL="${FLOCI_URL:-http://localhost:4566}"
OLLAMA_URL="${OLLAMA_URL:-http://localhost:11434}"
AWS_REGION="eu-west-2"
LAMBDA_NAME="genai-zvix-proxy"
API_NAME="genai-zvix-api"
MODEL_NAME="llama3.2:1b"
ZIP_FILE="${ROOT_DIR}/dist/zvix.zip"

export AWS_ACCESS_KEY_ID="test"
export AWS_SECRET_ACCESS_KEY="test"
export AWS_DEFAULT_REGION="${AWS_REGION}"

info() { echo -e "\033[34m[INFO]\033[0m $*"; }
ok()   { echo -e "\033[32m[OK]\033[0m   $*"; }
err()  { echo -e "\033[31m[ERR]\033[0m  $*" >&2; }
die()  { err "$*"; exit 1; }

# 1. Health checks
wait_for() {
    local service="$1"
    local url="$2"
    local retries=30
    info "Checking ${service} readiness at ${url}..."
    until curl -s -f -o /dev/null "${url}" || [ "${retries}" -eq 0 ]; do
        sleep 2
        retries=$((retries - 1))
    done
    [ "${retries}" -gt 0 ] || die "${service} failed to become healthy at ${url}"
    ok "${service} is reachable"
}

wait_for "Floci" "${FLOCI_URL}/_floci/health" || wait_for "Floci" "${FLOCI_URL}"
wait_for "Ollama" "${OLLAMA_URL}/api/tags"

# 2. Pre-pull model
info "Ensuring '${MODEL_NAME}' is loaded in Ollama..."
if docker ps --format '{{.Names}}' | grep -q "ollama-llm-engine"; then
    docker exec ollama-llm-engine ollama pull "${MODEL_NAME}"
else
    curl -s -X POST "${OLLAMA_URL}/api/pull" -d "{\"name\": \"${MODEL_NAME}\", \"stream\": false}" > /dev/null
fi
ok "Model ready"

# 3. Build artifact
mkdir -p "${ROOT_DIR}/dist"
rm -f "${ZIP_FILE}"
(cd "${ROOT_DIR}/src" && zip -q "${ZIP_FILE}" zvix.py)
ok "Built $(du -h "${ZIP_FILE}" | cut -f1) deployment artifact"

# 4. IAM Role
ROLE_NAME="zvix-lambda-role"
TRUST_POLICY='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'

ROLE_ARN=$(aws --endpoint-url="${FLOCI_URL}" iam get-role --role-name "${ROLE_NAME}" --query "Role.Arn" --output text 2>/dev/null || true)
if [ -z "${ROLE_ARN}" ] || [ "${ROLE_ARN}" = "None" ]; then
    ROLE_ARN=$(aws --endpoint-url="${FLOCI_URL}" iam create-role \
        --role-name "${ROLE_NAME}" \
        --assume-role-policy-document "${TRUST_POLICY}" \
        --query "Role.Arn" --output text)
    ok "Created IAM role: ${ROLE_NAME}"
fi

# 5. Lambda
LAMBDA_ARN=$(aws --endpoint-url="${FLOCI_URL}" lambda get-function --function-name "${LAMBDA_NAME}" --query "Configuration.FunctionArn" --output text 2>/dev/null || true)

ENV_VARS="Variables={OLLAMA_ENDPOINT=http://ollama:11434/api/generate,DEFAULT_MODEL=${MODEL_NAME},AWS_DEFAULT_REGION=${AWS_REGION}}"

if [ -n "${LAMBDA_ARN}" ] && [ "${LAMBDA_ARN}" != "None" ]; then
    info "Updating Lambda code and configuration..."
    aws --endpoint-url="${FLOCI_URL}" lambda update-function-code \
        --function-name "${LAMBDA_NAME}" \
        --zip-file "fileb://${ZIP_FILE}" > /dev/null
    aws --endpoint-url="${FLOCI_URL}" lambda update-function-configuration \
        --function-name "${LAMBDA_NAME}" \
        --environment "${ENV_VARS}" > /dev/null
else
    info "Creating Lambda function: ${LAMBDA_NAME}..."
    LAMBDA_ARN=$(aws --endpoint-url="${FLOCI_URL}" lambda create-function \
        --function-name "${LAMBDA_NAME}" \
        --runtime "python3.11" \
        --role "${ROLE_ARN}" \
        --handler "zvix.lambda_handler" \
        --zip-file "fileb://${ZIP_FILE}" \
        --timeout 60 \
        --memory-size 256 \
        --environment "${ENV_VARS}" \
        --query "FunctionArn" --output text)
    ok "Created Lambda function"
fi

# 6. API Gateway v2 HTTP API
API_ID=$(aws --endpoint-url="${FLOCI_URL}" apigatewayv2 get-apis --query "Items[?Name=='${API_NAME}'].ApiId" --output text 2>/dev/null || true)
if [ -z "${API_ID}" ] || [ "${API_ID}" = "None" ]; then
    API_ID=$(aws --endpoint-url="${FLOCI_URL}" apigatewayv2 create-api \
        --name "${API_NAME}" \
        --protocol-type HTTP \
        --query "ApiId" --output text)
    ok "Created HTTP API: ${API_ID}"
fi

INT_ID=$(aws --endpoint-url="${FLOCI_URL}" apigatewayv2 get-integrations --api-id "${API_ID}" --query "Items[?IntegrationUri=='${LAMBDA_ARN}'].IntegrationId" --output text 2>/dev/null || true)
if [ -z "${INT_ID}" ] || [ "${INT_ID}" = "None" ]; then
    INT_ID=$(aws --endpoint-url="${FLOCI_URL}" apigatewayv2 create-integration \
        --api-id "${API_ID}" \
        --integration-type AWS_PROXY \
        --integration-uri "${LAMBDA_ARN}" \
        --payload-format-version "2.0" \
        --query "IntegrationId" --output text)
fi

ROUTE_ID=$(aws --endpoint-url="${FLOCI_URL}" apigatewayv2 get-routes --api-id "${API_ID}" --query "Items[?RouteKey=='POST /v1/chat'].RouteId" --output text 2>/dev/null || true)
if [ -z "${ROUTE_ID}" ] || [ "${ROUTE_ID}" = "None" ]; then
    aws --endpoint-url="${FLOCI_URL}" apigatewayv2 create-route \
        --api-id "${API_ID}" \
        --route-key "POST /v1/chat" \
        --target "integrations/${INT_ID}" > /dev/null
fi

STAGE_EXISTS=$(aws --endpoint-url="${FLOCI_URL}" apigatewayv2 get-stage --api-id "${API_ID}" --stage-name '$default' --query "StageName" --output text 2>/dev/null || true)
if [ -z "${STAGE_EXISTS}" ] || [ "${STAGE_EXISTS}" = "None" ]; then
    aws --endpoint-url="${FLOCI_URL}" apigatewayv2 create-stage \
        --api-id "${API_ID}" \
        --stage-name '$default' \
        --auto-deploy > /dev/null
fi

GATEWAY_URL="${FLOCI_URL}/_aws/http-api/${API_ID}/v1/chat"
echo ""
ok "Deployment complete."
echo "Endpoint: ${GATEWAY_URL}"
