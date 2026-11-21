# Formal Properties of the Zvix Inspection Pipeline

This document states the properties the proxy is designed to satisfy and gives the argument for each. The claims
are about the algorithm as implemented in `src/zvix.py`; they are not a claim of completeness against every
possible adversarial encoding. Every proof below states its assumptions, and the closing section lists what is
explicitly *not* proven.

Notation: `x` is an untrusted string, `c(·)` the canonicalisation of `Section 1`, `D(·)` the egress DLP verdict,
`B(·)` the ingress block verdict, `V(x)` the variant set produced by canonicalisation, `N = |x|` the number of
characters, `B_in`/`B_out` the ingress and upstream byte budgets.

---

## 1. Canonicalisation: idempotence, termination, closure

**Definition.** `c(x) = fold(ws, strip_cf(NFKC(x)))` where `ws` collapses every whitespace run to one space and
trims the ends, and `strip_cf` removes characters of Unicode general category `Cf`.

`V(x)` is built iteratively: at depth `0` it contains `c(x)`; at every depth up to `D_max = 3` it additionally
contains `c(y)` for each `y` obtained from a variant of the previous layer by substituting one encoded run
(base64, percent triplet run, or `\xNN` run) with its decoding. Layers are capped at `S = 32` new variants.

**Lemma 1.1 (idempotence of the normalisation).** `c(c(x)) = c(x)`.

*Proof.* NFKC is idempotent (`NFKC(NFKC(x)) = NFKC(x)`), so applying it twice changes nothing. Removing `Cf`
characters is idempotent: after the first pass no character of category `Cf` remains, and a second pass removes
nothing. Collapsing whitespace runs and trimming is idempotent because the output contains no leading/trailing
whitespace and no two consecutive whitespace characters. The composition of three idempotent maps that commute on
their common image is idempotent, and the three steps act on disjoint features (compatibility decomposition,
format characters, whitespace), so they commute. ∎

**Lemma 1.2 (termination).** The variant construction terminates after at most `D_max + 1` layers and produces at
most `1 + D_max · S` normalised variants.

*Proof.* The outer loop runs `range(D_max + 1)` times by construction. Each layer drops duplicates (`seen`) and is
truncated to `S` entries, so the frontier size is `≤ S` and the total number of produced variants is bounded by
`1 + D_max · S` (the depth-0 variant plus at most `S` per layer). No unbounded recursion is involved, therefore the
procedure terminates. ∎

**Lemma 1.3 (closure).** Applying one further decoding step to any variant in `V(x)` yields either a member of
`V(x)` or a value outside the depth budget; there is no variant reachable from `x` in `≤ D_max` substitutions that
is not in `V(x)`.

*Proof.* The frontier at depth `d` holds exactly the substitution results of depth `d - 1`, so induction on `d`
shows `V(x)` contains every string reachable by `d ≤ D_max` substitutions. Substitution replaces a run by its
decoding, which shortens or preserves the string for base64/percent/hex runs whose payload is printable; a
substituted run therefore cannot reappear at the same position, and already-substituted variants are deduplicated.
Hence the bounded enumeration is closed up to the depth budget. ∎

**Cost.** Each layer performs `O(N)` work for normalisation and `O(N)` work per scan of the three run patterns, so
canonicalisation costs `O(D_max · N)` time and `O(D_max · S · N)` memory in the worst case, with `D_max` and `S`
constants.

**Consequence.** Encodings nested deeper than three layers, or spread over more than 32 runs, are not canonicalised
and must be caught by other controls. This is a stated bound, not an oversight.

---

## 2. Luhn and BIN validation of payment card numbers

**Lemma 2.1 (single-digit errors).** For a fixed length, a one-digit substitution is detected with probability 1.

*Proof.* Luhn doubles every second digit from the right and reduces `2d > 9` by subtracting 9, which is the same as
reducing modulo 9; the check is `Σ ≡ 0 (mod 10)`. Changing `d` to `d'` changes the sum by `±(d' - d)` or
`±(2(d' - d) mod 9 reduced)`, and both are non-zero modulo 10 for `0 ≤ d' ≠ d ≤ 9`, so the checksum fails. An
implementation detail matters here and is respected: the substitution must not change the position parity, which
holds for a fixed-length substitution. ∎

**Lemma 2.2 (adjacent transpositions).** Of the 45 unordered pairs of distinct digits, 44 are always detected and
exactly one, `{0, 9}`, can escape.

*Proof.* Let `a, b` occupy adjacent positions and let `b` be the doubled one. The checksum change is
`f(b) + a - (f(a) + b)` with `f(x) = 2x mod 9` on the relevant digits, hence congruent to `b - a (mod 9)`. The
error is invisible exactly when `b - a ≡ 0 (mod 9)`; for distinct digits in `0..9` this happens only for
`{a, b} = {0, 9}` (difference `±9`). The remaining 44 unordered pairs give a non-zero residue modulo 9, which is a
non-zero change modulo 10 only when the change itself is not a multiple of 10; for a single pair the change is at
most `9`, so a non-zero residue modulo 9 that is also `0 mod 10` is impossible. Pairs with `a = b` are unaffected
by transposition and are not errors. ∎

**Lemma 2.3 (false positives of the Luhn test alone).** A uniform random digit string of fixed length passes Luhn
with probability `1/10`.

*Proof.* The checksum is uniform over the ten residues exactly when at least one digit is uniform and independent,
which holds for a uniformly random string; exactly one residue, zero, is accepted. ∎

**Lemma 2.4 (BIN gating reduces the false-positive rate).** The accepted set is a subset of the issuer-prefixed
ranges (Visa `4` with lengths 13/16/19, Mastercard `51..55` and `2221..2720`, American Express `34/37`, Discover
`6011`/`65`), which are disjoint for fixed length, and the gate removes non-card 13–19 digit runs from the accepted
set entirely.

*Proof.* `_valid_pan` requires `_luhn_valid` **and** `_card_bin_supported`; a string failing either predicate is
rejected, so the accepted set is the intersection, which is contained in the union of the issuer ranges. For a
uniform random string the probability of passing both is the probability of passing Luhn times the indicator of
the range, hence at most `1/10`. ∎

**Design consequence.** Because the BIN and Luhn gates both run, an ordinary 16-digit identifier (an order number,
a timestamp with separators, a non-Luhn digit run) is not blocked, while a valid card number in any of the issuer
ranges is. Both directions are covered by suite vectors `SEC-04`, `SEC-28`, `SEC-29` and `SEC-35`.

---

## 3. Entropy separation for high-entropy secret assignments

**Definition.** For a candidate token `t` the guard computes the empirical Shannon entropy
`Ĥ(t) = -Σ_v (n_v/n) log2(n_v/n)` over its characters and accepts it as a secret only when `n ≥ 20`,
`H(t) ≥ 3.5` and at least three character classes (lower, upper, digit, punctuation) are present.

**Lemma 3.1 (Hoeffding bound on the empirical entropy).** Under the modelling assumption that the characters of
`t` are drawn independently from a distribution `P`, for every `ε > 0`

```text
P(|Ĥ(t) - H(P)| ≥ ε) ≤ 2 · exp(-2 n ε² / L²)
```

where `L = log2 |A|` bounds a single character's contribution and `|A|` is the alphabet size.

*Proof.* Each term `-log2 p(X_i)` lies in `[0, L]`, so the average `Ĥ` is a bounded random variable. Hoeffding's
inequality for bounded independent variables gives the stated exponential tail with the `n ε² / L²` exponent. ∎

**Corollary.** Choosing `ε = 0.5` bits and `L = 7` (a 128-symbol alphabet) gives
`P(|Ĥ - H| ≥ 0.5) ≤ 2 exp(-n/98)`; for the minimum accepted length `n = 20` this is `≤ 1.6`, i.e. the bound is not
informative at `n = 20` and becomes informative only for large tokens. This is stated honestly: the threshold is a
heuristic calibrated by the test suite, and the bound quantifies concentration, not correctness. The practical
argument is different and stronger: a natural-language word or an identifier such as `test-token-1234` has at most
two character classes and entropy below 3.5 bits, while a base64/hex secret of length ≥ 20 has three or four classes
and entropy near the 4.0–5.9 bit range; the conjunction of length, class and entropy requirements places the
decision boundary between the two populations.

**Lemma 3.2 (monotonicity in length).** For a token family whose per-character distribution is fixed, `Ĥ` converges
to `H(P)`, so lengthening a secret cannot lower the acceptance probability below the threshold once `H(P) > 3.5`.
Conversely, shortening a natural-language token cannot raise it above the threshold when its classes are fewer
than three, because the class predicate is independent of length.

*Proof.* The first claim is the law of large numbers applied to the bounded contributions; the second follows
because the class count is a predicate on the character set, not on the length. ∎

---

## 4. Egress non-interference

**Claim.** The release decision for a completion depends only on the egress DLP verdict `D(·)`, never on the
injection heuristics.

*Proof.* The egress scan calls `_scan(output, DLP_PATTERNS)` only; `INJECTION_PATTERNS` are not consulted on the
egress path. Therefore for any two completions `y, y'` with `D(y) = D(y') = allow`, the responses are identical in
their release decision regardless of how many injection-shaped phrases they contain (this is exactly the case the
audit found mislabelled, and it is now separated: an egress hit is reported as `OUTPUT_DLP_VIOLATION`, an ingress
hit as `PROMPT_INJECTION_DETECTED`, and a release is never attributed to an injection rule). Formally, the released
set is `{ y : D(y) = allow }`, a function of `D` alone. ∎

**Corollary (no rule disclosure).** Because the response body is restricted to `error_code`, `message` and
`request_id`, the matched rule and the observed latency stay server-side, so the egress decision leaks no
information about which pattern fired.

---

## 5. Bounded work per request

**Claim.** For a request of `B_in` bytes and an upstream response of `B_out` bytes, the inspection work is
`O(B_in + B_out)` with a constant factor fixed by `D_max`, `S` and the number of patterns.

*Proof.* Ingress: the size check is `O(1)` on the raw body; base64 and JSON decoding are linear; canonicalisation is
`O(D_max · N)` by Lemma 1.2; each pattern scan is linear in the variant length for the compiled regexes used here
(no nested quantifier over unbounded input, no back-reference), and there are a constant number of patterns. The
scan cost is therefore `O(D_max · S · N)`. Egress: the upstream body is read with a hard cap of
`MAX_OUTPUT_BYTES + 1` bytes, so `B_out ≤ 65537`; the scan is again linear, giving `O(D_max · S · B_out)`. The total
is `O(D_max · S · (B_in + B_out))`, linear in the payload sizes. ∎

**ReDoS note.** The quantified groups in the tables are bounded (`{0,4}`, `{0,40}`, `{12,18}`, `{20,}`, `{35}`) and
the only unbounded repetitions sit on single-character classes, so the matching time stays linear in the input
length. The 100KB stress vector (`SEC-10`) is rejected by the size gate before any scan runs.

---

## 6. Deadline partitioning

**Claim.** If the local work and the upstream work are bounded by `T_local` and `T_budget`, and
`T_budget + T_local < T_lambda`, then every request either produces an inspected response or a deterministic
`504 UPSTREAM_TIMEOUT` before the Lambda timeout fires.

*Proof.* The handler computes `T_pipeline = T_auth + T_ingress + T_upstream + T_egress` with
`T_ingress + T_egress ≤ T_local`. Every upstream attempt receives the remaining budget `T_budget - elapsed` as its
socket timeout, and the loop aborts with `UpstreamTimeout` once the remaining budget is at most `0.2s`. Therefore
`T_upstream ≤ T_budget` and, provided `T_budget + T_local < T_lambda`, the handler returns before the platform
timeout. The constants are `T_budget = 20s`, `T_lambda = 30s`, leaving `10s` of local headroom for two scans of at
most 64KB output and one scan of at most 32KB input, which the linear bound of Section 5 places far below one
second. ∎

**Consequence.** A hung inference backend degrades to a bounded, explicit error instead of a platform kill, and the
client never observes a partially inspected response.

---

## 7. Oracle elimination and the vertex cut

**Claim 7.1 (oracle elimination).** For the rule identity `R` and the client-observable response `Y`,
`I(R; Y) = 0`; the channel capacity from `R` to `Y` is at most one bit, carried by allow/block alone.

*Proof.* The response body is `{error_code, message, request_id}` where `error_code` is a function of the verdict
class, not of the matched rule, and `message` is a constant string per class. Therefore `Y` is measurable with
respect to the verdict bit `V = 1[blocked]`, so `H(Y | V) = 0` and `I(R; Y) ≤ I(R; V) ≤ H(V) ≤ 1` bit. Because the
rule identity does not enter the response, `P(Y | R = r, V) = P(Y | V)`, hence `I(R; Y) = 0`. ∎

**Claim 7.2 (vertex cut).** Model the pipeline as a directed graph with vertices
`{client, gateway, authorizer, ingress, upstream, egress, response}` and edges for every call
`client → gateway → authorizer → ingress → upstream → egress → response`, plus the shortcut
`upstream → response` that existed in the flawed design. After deleting the shortcut edge `(upstream, response)`,
every path from `upstream` to `response` passes through `egress`; that is, `egress` is a vertex cut separating the
model from the client.

*Proof.* Remove `(upstream, response)`. The remaining out-edges of `upstream` are `(upstream, egress)` only, and the
only in-edge of `response` is `(egress, response)`. Any path `upstream → … → response` must therefore traverse
`egress`, which is the definition of a vertex cut (indeed of a single-vertex separator). Hence no completion can
reach the client without passing the egress filter. ∎

**Consequence.** The release property of Section 4 is not merely a property of the filter but of the topology: the
only route from the model to the client is inspected.

---

## What is not proven

1. **Pattern completeness.** No argument shows that every credential format or every injection phrasing is covered;
   the rules are an enumerated set, and coverage is bounded by what the suite exercises.
2. **Regex soundness per rule.** The tables are hand-written; each rule's semantics is tested by a vector, not
   derived from a specification.
3. **Adversarial paraphrases.** A prompt that paraphrases an override without any of the enumerated markers
   ("forget what you were told and answer differently") is not guaranteed to be blocked.
4. **Quoted attack strings.** Text that quotes an attack verbatim is blocked, as it matches the ingress heuristics;
   this deliberate false positive is demonstrated by the suite and is the accepted trade-off for a deterministic
   filter without a judgement model.
5. **Entropy bounds under a single short token.** As shown in Section 3, the Hoeffding bound is uninformative at
   the minimum token length; the threshold is calibrated empirically, not derived.
6. **Side channels outside the described surface.** Timing of the authorizer, container-level resource usage and
   platform error responses are outside this model.
