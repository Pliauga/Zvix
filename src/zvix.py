"""Zvix security proxy: ingress and egress inspection in front of an LLM backend."""

import base64
import binascii
import hashlib
import hmac
import json
import logging
import math
import os
import re
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger()
logger.setLevel(logging.INFO)

OLLAMA_ENDPOINT = os.environ.get('OLLAMA_ENDPOINT', 'http://ollama:11434/api/generate')
DEFAULT_MODEL = os.environ.get('DEFAULT_MODEL', 'llama3.2:1b')
TOTAL_UPSTREAM_BUDGET = float(os.environ.get('TOTAL_UPSTREAM_BUDGET_SECONDS', '20.0'))
MAX_INPUT_BYTES = int(os.environ.get('MAX_INPUT_BYTES', '32768'))
MAX_OUTPUT_BYTES = int(os.environ.get('MAX_OUTPUT_BYTES', '65536'))
MAX_DECODE_DEPTH = int(os.environ.get('MAX_DECODE_DEPTH', '3'))
MIN_DEADLINE_REMAINING = 0.2
MIN_SECRET_LENGTH = 20
MIN_ENTROPY_BITS = 3.5
MIN_CHAR_CLASSES = 3
MAX_DECODED_SEGMENTS = 32
CANARY_PROMPT = '__zvix_canary__'

DLP_VIOLATION = 'DATA_LOSS_PREVENTION_VIOLATION'
INJECTION_VIOLATION = 'PROMPT_INJECTION_DETECTED'
OUTPUT_VIOLATION = 'OUTPUT_DLP_VIOLATION'


class RequestRejected(Exception):
    """A request that must be answered with a deterministic error response."""

    def __init__(self, status_code: int, error_code: str, message: str,
                 stage: str = 'ingress', rule: Optional[str] = None) -> None:
        super().__init__(error_code)
        self.status_code = status_code
        self.error_code = error_code
        self.message = message
        self.stage = stage
        self.rule = rule


class UpstreamTimeout(RuntimeError):
    """Raised when the shared upstream budget is exhausted."""


class UpstreamResponseTooLarge(RuntimeError):
    """Raised when the upstream body exceeds the configured output cap."""


class UpstreamError(RuntimeError):
    """Raised when an upstream attempt fails with a non-transport error."""


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _character_classes(value: str) -> int:
    return sum(
        bool(re.search(pattern, value))
        for pattern in (r'[a-z]', r'[A-Z]', r'[0-9]', r'[^A-Za-z0-9]')
    )


def _looks_like_secret(match: re.Match) -> bool:
    token = match.group('token')
    if len(token) < MIN_SECRET_LENGTH:
        return False
    if _character_classes(token) < MIN_CHAR_CLASSES:
        return False
    return _shannon_entropy(token) >= MIN_ENTROPY_BITS


def _luhn_valid(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _card_bin_supported(digits: str) -> bool:
    prefix_2 = int(digits[:2])
    prefix_4 = int(digits[:4])
    if digits[0] == '4':
        return len(digits) in (13, 16, 19)
    if 51 <= prefix_2 <= 55:
        return len(digits) == 16
    if 2221 <= prefix_4 <= 2720:
        return len(digits) == 16
    if prefix_2 in (34, 37):
        return len(digits) == 15
    if digits[:4] == '6011' or prefix_2 == 65:
        return len(digits) == 16
    return False


def _valid_pan(match: re.Match) -> bool:
    digits = re.sub(r'\D', '', match.group(0))
    if not 13 <= len(digits) <= 19:
        return False
    if not _card_bin_supported(digits):
        return False
    return _luhn_valid(digits)


_PAN_PATTERN = re.compile(r'(?<![0-9])(?:[0-9][ -]?){12,18}[0-9](?![0-9])')

Rule = Tuple[str, re.Pattern, Optional[Callable[[re.Match], bool]]]

DLP_PATTERNS: List[Rule] = [
    ('AWS_ACCESS_KEY_ID', re.compile(r'\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b', re.IGNORECASE), None),
    (
        'ANTHROPIC_API_KEY',
        re.compile(r'\bsk-ant-(?:api\d{2}-)?[a-zA-Z0-9_-]{20,}\b'),
        None,
    ),
    (
        'OPENAI_API_KEY',
        re.compile(r'\bsk-(?:proj|svcacct)-[a-zA-Z0-9_-]{20,}\b'),
        None,
    ),
    ('LEGACY_OPENAI_KEY', re.compile(r'\bsk-[a-zA-Z0-9]{32,}\b'), None),
    ('SLACK_TOKEN', re.compile(r'\bxox[baprs]-[0-9a-zA-Z-]{10,}\b'), None),
    ('GOOGLE_API_KEY', re.compile(r'\bAIza[0-9A-Za-z_-]{35}\b', re.IGNORECASE), None),
    ('GOOGLE_OAUTH_TOKEN', re.compile(r'\bya29\.[0-9A-Za-z_-]{20,}\b', re.IGNORECASE), None),
    ('GITHUB_FINE_GRAINED_PAT', re.compile(r'\bgithub_pat_[a-zA-Z0-9_]{22,}\b'), None),
    ('GITHUB_TOKEN', re.compile(r'\bgh[pousr]_[A-Za-z0-9_]{36,}\b'), None),
    ('PRIVATE_KEY_BLOCK', re.compile(r'-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----', re.IGNORECASE), None),
    ('SESSION_JWT', re.compile(r'\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}'), None),
    (
        'BEARER_TOKEN',
        re.compile(r'\bBearer\s+(?P<token>[A-Za-z0-9._\-]{20,})', re.IGNORECASE),
        _looks_like_secret,
    ),
    (
        'SECRET_ASSIGNMENT',
        re.compile(
            r'(?:api[_-]?key|secret|token|password)\s*[:=]\s*[\'"]?(?P<token>[A-Za-z0-9._\-]{20,})',
            re.IGNORECASE,
        ),
        _looks_like_secret,
    ),
    ('CREDIT_CARD_PAN', _PAN_PATTERN, _valid_pan),
    (
        'UK_NATIONAL_INSURANCE_NUMBER',
        re.compile(
            r'\b(?:[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]|QQ|ZZ)\s*\d{2}\s*\d{2}\s*\d{2}\s*[A-D]\b',
            re.IGNORECASE,
        ),
        None,
    ),
]

INJECTION_PATTERNS: List[Rule] = [
    (
        'INSTRUCTION_OVERRIDE',
        re.compile(
            r'(?:ignore|disregard|forget|bypass|override)\b\s+'
            r'(?:(?:all|any|the|of|every)\s+){0,4}'
            r'(?:previous|prior|earlier|system|initial|above|preceding)\s+'
            r'(?:instructions|prompts|directions|rules|guidelines)'
        ),
        None,
    ),
    (
        'SYSTEM_PROMPT_EXTRACTION',
        re.compile(
            r'(?:reveal|show|print|output|repeat|display|dump|expose|leak)\b'
            r'[^.\n]{0,40}'
            r'(?:system\s+prompt|system\s+instructions|initial\s+instructions|'
            r'hidden\s+instructions|developer\s+message)'
        ),
        None,
    ),
    ('SYSTEM_PROMPT_EXTRACTION', re.compile(r'system\s+prompt\s+override'), None),
    (
        'JAILBREAK_PERSONA',
        re.compile(
            r'(?:jailbreak\s+mode|you\s+are\s+(?:now\s+)?dan\b|act\s+as\s+dan\b|'
            r'do\s+anything\s+now|developer\s+mode\s+enabled|unrestricted\s+mode)'
        ),
        None,
    ),
    (
        'DELIMITER_INJECTION_ATTACK',
        re.compile(r'(?:```\s*system|\[system\]|<\|im_start\|>\s*system|<system>)'),
        None,
    ),
]

_BASE64_SEGMENT = re.compile(r'[A-Za-z0-9+/=_-]{16,}')
_PERCENT_RUN = re.compile(r'(?:%[0-9A-Fa-f]{2})+')
_HEX_ESCAPE_RUN = re.compile(r'(?:\\x[0-9A-Fa-f]{2})+')


def _strip_format_characters(text: str) -> str:
    return ''.join(char for char in text if unicodedata.category(char) != 'Cf')


def _normalize(text: str) -> str:
    decomposed = unicodedata.normalize('NFKC', text)
    stripped = _strip_format_characters(decomposed)
    return re.sub(r'\s+', ' ', stripped).strip()


def _decode_base64_segment(segment: str) -> Optional[str]:
    padded = segment + '=' * (-len(segment) % 4)
    try:
        raw = base64.b64decode(padded, altchars=b'-_', validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError:
        return None
    if text.strip() and all(char.isprintable() or char in '\r\n\t' for char in text):
        return text
    return None


def _decode_payloads(text: str) -> List[str]:
    """Substitute each encoded run in place so the surrounding words stay adjacent."""
    variants: List[str] = []
    for match in _PERCENT_RUN.finditer(text):
        replacement = urllib.parse.unquote(match.group(0))
        if replacement and replacement != match.group(0):
            variants.append(text.replace(match.group(0), replacement))
    for match in _HEX_ESCAPE_RUN.finditer(text):
        replacement = ''.join(
            chr(int(pair, 16)) for pair in re.findall(r'\\x([0-9A-Fa-f]{2})', match.group(0))
        )
        if replacement and replacement != match.group(0):
            variants.append(text.replace(match.group(0), replacement))
    for match in _BASE64_SEGMENT.finditer(text):
        if len(variants) >= MAX_DECODED_SEGMENTS:
            break
        replacement = _decode_base64_segment(match.group(0))
        if replacement:
            variants.append(text.replace(match.group(0), replacement))
    return variants


def canonicalize_text(text: str, max_depth: int = MAX_DECODE_DEPTH) -> List[str]:
    """Return the normalized text plus every payload decoded within max_depth layers."""
    if not isinstance(text, str) or not text:
        return []
    variants: List[str] = []
    seen = set()
    frontier: List[str] = [text]
    for _depth in range(max_depth + 1):
        pending: List[str] = []
        for chunk in frontier:
            normalized = _normalize(chunk)
            if normalized and normalized not in seen:
                seen.add(normalized)
                variants.append(normalized)
            for decoded in _decode_payloads(chunk):
                if decoded not in seen:
                    pending.append(decoded)
        frontier = pending[:MAX_DECODED_SEGMENTS]
        if not frontier:
            break
    return variants


def _scan(text: str, rules: List[Rule]) -> Tuple[bool, Optional[str]]:
    variants = canonicalize_text(text)
    for rule, pattern, validator in rules:
        for variant in variants:
            for candidate in (variant, variant.lower()):
                for match in pattern.finditer(candidate):
                    if validator is None or validator(match):
                        return True, rule
    return False, None


def scan_ingress(text: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """Inspect a prompt for secret leakage and prompt-injection attempts."""
    blocked, rule = _scan(text, DLP_PATTERNS)
    if blocked:
        return True, DLP_VIOLATION, rule
    blocked, rule = _scan(text, INJECTION_PATTERNS)
    if blocked:
        return True, INJECTION_VIOLATION, rule
    return False, None, None


def scan_egress(text: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """Inspect a model completion for secret leakage only."""
    blocked, rule = _scan(text, DLP_PATTERNS)
    if blocked:
        return True, OUTPUT_VIOLATION, rule
    return False, None, None


def scan_content(text: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """Backwards-compatible alias for the ingress inspection."""
    return scan_ingress(text)


def _upstream_candidates() -> List[str]:
    candidates = [OLLAMA_ENDPOINT]
    fallback = os.environ.get('OLLAMA_FALLBACK_ENDPOINT')
    if fallback and fallback not in candidates:
        candidates.append(fallback)
    if 'ollama:' in OLLAMA_ENDPOINT:
        local = OLLAMA_ENDPOINT.replace('ollama:', 'localhost:')
        if local not in candidates:
            candidates.append(local)
    return candidates


def query_llm(prompt: str, model: str, deadline: Optional[float] = None) -> Dict[str, Any]:
    """Dispatch the prompt upstream, honouring one shared monotonic deadline."""
    canary = os.environ.get('ZVIX_CANARY_RESPONSE')
    if canary and prompt == CANARY_PROMPT:
        return {'model': model, 'response': canary, 'done': True}
    if os.environ.get('MOCK_LLM_MODE', '').lower() in ('true', '1', 'yes'):
        return {
            'model': model,
            'response': f'Sanitized response for: "{prompt[:60]}"',
            'done': True,
        }
    if deadline is None:
        deadline = time.monotonic() + TOTAL_UPSTREAM_BUDGET

    max_tokens = int(os.environ.get('MAX_GENERATE_TOKENS', '32'))
    payload = json.dumps({
        'model': model,
        'prompt': prompt,
        'stream': False,
        'options': {'num_predict': max_tokens},
    }).encode('utf-8')
    last_error: Optional[BaseException] = None
    for url in _upstream_candidates():
        remaining = deadline - time.monotonic()
        if remaining <= MIN_DEADLINE_REMAINING:
            raise UpstreamTimeout('Upstream budget exhausted before the next attempt')
        try:
            request = urllib.request.Request(
                url,
                data=payload,
                headers={'Content-Type': 'application/json'},
                method='POST',
            )
            with urllib.request.urlopen(request, timeout=remaining) as response:
                if response.status != 200:
                    last_error = UpstreamError(f'Upstream returned HTTP {response.status}')
                    continue
                raw = response.read(MAX_OUTPUT_BYTES + 1)
                if len(raw) > MAX_OUTPUT_BYTES:
                    raise UpstreamResponseTooLarge('Upstream body exceeded the configured cap')
                return json.loads(raw.decode('utf-8'))
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = exc
            continue

    if deadline - time.monotonic() <= MIN_DEADLINE_REMAINING:
        raise UpstreamTimeout('Upstream budget exhausted') from last_error
    raise last_error or UpstreamError('No LLM endpoint reachable')


def _payload_fingerprint(payload: Optional[str]) -> Optional[str]:
    if not payload:
        return None
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()[:12]


def _log_decision(request_id: str, stage: str, decision: str, violation: Optional[str] = None,
                  rule: Optional[str] = None, latency_ms: float = 0.0,
                  payload: Optional[str] = None) -> None:
    entry = {
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'request_id': request_id,
        'stage': stage,
        'decision': decision,
        'violation_type': violation,
        'rule_triggered': rule,
        'latency_ms': round(latency_ms, 2),
        'payload_sha256_prefix': _payload_fingerprint(payload),
    }
    logger.info(json.dumps(entry, sort_keys=True))


def _request_id(event: Any, context: Any) -> str:
    if isinstance(event, dict):
        request_context = event.get('requestContext')
        if isinstance(request_context, dict) and request_context.get('requestId'):
            return str(request_context['requestId'])
    identifier = getattr(context, 'aws_request_id', None)
    if identifier:
        return str(identifier)
    return hashlib.sha256(str(time.time_ns()).encode('utf-8')).hexdigest()[:16]


def _authorize(event: Any) -> None:
    expected = os.environ.get('ZVIX_API_TOKEN', '')
    if not expected:
        return
    headers: Dict[str, Any] = {}
    if isinstance(event, dict) and isinstance(event.get('headers'), dict):
        headers = {str(key).lower(): value for key, value in event['headers'].items()}
    supplied = headers.get('authorization', '')
    if isinstance(supplied, str) and supplied.lower().startswith('bearer '):
        supplied = supplied[7:]
    matched = False
    if isinstance(supplied, str):
        try:
            matched = hmac.compare_digest(supplied, expected)
        except TypeError:
            matched = False
    if not matched:
        raise RequestRejected(401, 'UNAUTHORIZED', 'A valid bearer token is required.')


def _enforce_input_limit(size: int) -> None:
    if size > MAX_INPUT_BYTES:
        raise RequestRejected(
            413,
            'PAYLOAD_TOO_LARGE',
            f'Request body exceeds the {MAX_INPUT_BYTES} byte limit.',
        )


def _parse_body(event: Any) -> Dict[str, Any]:
    raw: Any = event
    if isinstance(event, dict) and 'body' in event:
        raw = event.get('body')
    if isinstance(raw, dict):
        _enforce_input_limit(len(json.dumps(raw).encode('utf-8')))
        return raw
    if not isinstance(raw, str):
        return {}
    _enforce_input_limit(len(raw.encode('utf-8')))
    if isinstance(event, dict) and event.get('isBase64Encoded') is True:
        try:
            raw = base64.b64decode(raw, validate=True).decode('utf-8')
        except UnicodeDecodeError:
            raise RequestRejected(400, 'INVALID_JSON_PAYLOAD', 'Request body is not valid UTF-8.')
        except (binascii.Error, ValueError):
            raise RequestRejected(400, 'INVALID_BASE64_PAYLOAD', 'Malformed base64 request body.')
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        raise RequestRejected(400, 'INVALID_JSON_PAYLOAD', 'Malformed JSON payload.')
    if not isinstance(parsed, dict):
        raise RequestRejected(400, 'INVALID_JSON_PAYLOAD', 'Request body must be a JSON object.')
    return parsed


def http_response(status_code: int, data: Dict[str, Any]) -> Dict[str, Any]:
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-Proxy-Security': 'Zvix-DLP-v2',
            'Cache-Control': 'no-store',
        },
        'body': json.dumps(data),
    }


def _process(event: Any, request_id: str, started: float) -> Dict[str, Any]:
    _authorize(event)
    body = _parse_body(event)

    prompt = body.get('prompt')
    if not isinstance(prompt, str) or not prompt:
        raise RequestRejected(400, 'MISSING_PROMPT', 'A non-empty string "prompt" field is required.')

    model = body.get('model') or DEFAULT_MODEL
    if not isinstance(model, str):
        model = DEFAULT_MODEL

    blocked, violation, rule = scan_ingress(prompt)
    elapsed = (time.time() - started) * 1000
    if blocked:
        raise RequestRejected(403, violation, 'Request dropped: security policy violation.', rule=rule)
    _log_decision(request_id, 'ingress', 'ALLOW', latency_ms=elapsed, payload=prompt)

    deadline = time.monotonic() + TOTAL_UPSTREAM_BUDGET
    llm_data = query_llm(prompt, model, deadline)
    output_text = llm_data.get('response', '')
    if not isinstance(output_text, str):
        output_text = str(output_text)
    _log_decision(request_id, 'upstream', 'ALLOW', latency_ms=(time.time() - started) * 1000)

    blocked, violation, rule = scan_egress(output_text)
    elapsed = (time.time() - started) * 1000
    if blocked:
        raise RequestRejected(
            403,
            violation,
            'Model output suppressed by the egress DLP filter.',
            stage='egress',
            rule=rule,
        )
    _log_decision(request_id, 'egress', 'ALLOW', latency_ms=elapsed, payload=output_text)

    return http_response(200, {
        'status': 'allowed',
        'model': model,
        'response': output_text,
        'latency_ms': round(elapsed, 2),
        'request_id': request_id,
    })


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    started = time.time()
    request_id = _request_id(event, context)

    try:
        return _process(event, request_id, started)
    except RequestRejected as exc:
        _log_decision(
            request_id,
            exc.stage,
            'BLOCK',
            violation=exc.error_code,
            rule=exc.rule,
            latency_ms=(time.time() - started) * 1000,
        )
        return http_response(exc.status_code, {
            'error_code': exc.error_code,
            'message': exc.message,
            'request_id': request_id,
        })
    except UpstreamTimeout:
        _log_decision(request_id, 'upstream', 'ERROR', violation='UPSTREAM_TIMEOUT',
                      latency_ms=(time.time() - started) * 1000)
        return http_response(504, {
            'error_code': 'UPSTREAM_TIMEOUT',
            'message': 'Security proxy failure: upstream LLM timed out.',
            'request_id': request_id,
        })
    except UpstreamResponseTooLarge:
        _log_decision(request_id, 'upstream', 'ERROR', violation='UPSTREAM_RESPONSE_TOO_LARGE',
                      latency_ms=(time.time() - started) * 1000)
        return http_response(502, {
            'error_code': 'UPSTREAM_RESPONSE_TOO_LARGE',
            'message': 'Security proxy failure: upstream response exceeded the configured limit.',
            'request_id': request_id,
        })
    except urllib.error.URLError as exc:
        logger.error('Upstream LLM unavailable: %s', exc)
        _log_decision(request_id, 'upstream', 'ERROR', violation='UPSTREAM_LLM_UNAVAILABLE',
                      latency_ms=(time.time() - started) * 1000)
        return http_response(500, {
            'error_code': 'UPSTREAM_LLM_UNAVAILABLE',
            'message': 'Security proxy failure: upstream LLM unreachable.',
            'request_id': request_id,
        })
    except Exception:
        logger.exception('Internal proxy processing error')
        _log_decision(request_id, 'ingress', 'ERROR', violation='INTERNAL_SECURITY_PROXY_ERROR',
                      latency_ms=(time.time() - started) * 1000)
        return http_response(500, {
            'error_code': 'INTERNAL_SECURITY_PROXY_ERROR',
            'message': 'Security proxy failure: internal processing error.',
            'request_id': request_id,
        })


def authorize(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """API Gateway REQUEST authorizer entry point using a constant-time comparison."""
    try:
        _authorize(event)
    except RequestRejected:
        return {'isAuthorized': False}
    return {'isAuthorized': True, 'context': {'principal': 'zvix-client'}}
