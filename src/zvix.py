import json
import logging
import os
import time
import urllib.error
import urllib.request
from typing import Any, Dict

logger = logging.getLogger()
logger.setLevel(logging.INFO)

OLLAMA_ENDPOINT = os.environ.get('OLLAMA_ENDPOINT', 'http://ollama:11434/api/generate')
DEFAULT_MODEL = os.environ.get('DEFAULT_MODEL', 'llama3.2:1b')
INSPECTION_TIMEOUT = int(os.environ.get('INSPECTION_TIMEOUT_SECONDS', '30'))


def query_llm(prompt: str, model: str) -> Dict[str, Any]:
    if os.environ.get('MOCK_LLM_MODE', '').lower() in ('true', '1', 'yes'):
        return {
            'model': model,
            'response': f'Sanitized response for: "{prompt[:60]}"',
            'done': True,
        }

    payload = json.dumps({'model': model, 'prompt': prompt, 'stream': False}).encode('utf-8')
    candidates = [OLLAMA_ENDPOINT]
    fallback = os.environ.get('OLLAMA_FALLBACK_ENDPOINT')
    if fallback and fallback not in candidates:
        candidates.append(fallback)
    elif 'ollama:' in OLLAMA_ENDPOINT:
        candidates.append(OLLAMA_ENDPOINT.replace('ollama:', 'localhost:'))

    last_error = None
    for url in candidates:
        try:
            req = urllib.request.Request(
                url,
                data=payload,
                headers={'Content-Type': 'application/json'},
                method='POST',
            )
            with urllib.request.urlopen(req, timeout=INSPECTION_TIMEOUT) as resp:
                if resp.status == 200:
                    return json.loads(resp.read().decode('utf-8'))
                raise RuntimeError(f'Upstream returned HTTP {resp.status}')
        except urllib.error.URLError as e:
            last_error = e
            continue

    raise last_error or RuntimeError('No LLM endpoint reachable')


def http_response(status_code: int, data: Dict[str, Any]) -> Dict[str, Any]:
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-Proxy-Security': 'Zvix-DLP-v1',
            'Cache-Control': 'no-store',
        },
        'body': json.dumps(data),
    }


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    start_time = time.time()

    try:
        raw_body = event.get('body') if isinstance(event, dict) and 'body' in event else event
        if isinstance(raw_body, str):
            try:
                body = json.loads(raw_body)
            except json.JSONDecodeError:
                return http_response(400, {
                    'error_code': 'INVALID_JSON_PAYLOAD',
                    'message': 'Malformed JSON payload.',
                })
        elif isinstance(raw_body, dict):
            body = raw_body
        else:
            body = {}

        prompt = body.get('prompt')
        if not prompt or not isinstance(prompt, str):
            return http_response(400, {
                'error_code': 'MISSING_PROMPT',
                'message': 'A non-empty string "prompt" field is required.',
            })

        model = body.get('model', DEFAULT_MODEL)
        llm_data = query_llm(prompt, model)
        output_text = llm_data.get('response', '')

        latency = round((time.time() - start_time) * 1000, 2)
        return http_response(200, {
            'status': 'allowed',
            'model': model,
            'response': output_text,
            'latency_ms': latency,
        })

    except urllib.error.URLError as e:
        logger.error(f'Upstream LLM unavailable: {e}')
        return http_response(500, {
            'error_code': 'UPSTREAM_LLM_UNAVAILABLE',
            'message': 'Security proxy failure: upstream LLM unreachable.',
        })
    except Exception as e:
        logger.error(f'Internal proxy processing error: {e}', exc_info=True)
        return http_response(500, {
            'error_code': 'INTERNAL_SECURITY_PROXY_ERROR',
            'message': 'Security proxy failure: internal processing error.',
        })
