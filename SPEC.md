# Conformance contract

This document is what an implementation needs to run the corpus and be graded.
It does not define a receipt format — it grades verifiers of the formats that
already exist.

## Vector format

Each file in `vectors/` is one self-contained case:

```jsonc
{
  "id":    "02-attestation-control-never-ran",
  "tier":  "attestation",              // "envelope" | "attestation"
  "title": "Perfect signature, control that could never execute",
  "why":   "…the failure this guards against, in a sentence…",

  "receipt":  "eyJhbGciOiJFZERTQSIs…",  // compact JWS
  "jwks":     { "keys": [ … ] },         // the ONLY trust anchor
  "manifest": "capability:\n  id: …",    // capability manifest, verbatim YAML
  "inputs":   { "amount": 42 },          // the call's inputs (optional)

  "expect": {
    "envelope_valid": true,
    "attestation_conformant": false,     // omitted for tier-1 vectors
    "failing_checks": ["controls_enforceable"]
  }
}
```

`manifest` and `inputs` are embedded rather than referenced by path so a vector
can be handed to an implementation in any language with nothing else attached.

## Runner contract

```
runner --verifier "<command template>"
```

Placeholders are replaced with paths to temp files holding the vector's
artifacts:

| Placeholder | Contents |
|---|---|
| `{receipt}` | the compact receipt (also written to stdin) |
| `{jwks}` | the JWKS |
| `{manifest}` | the capability manifest YAML |
| `{inputs}` | the call's inputs JSON |

When a vector carries no `manifest` or `inputs`, the runner removes that
placeholder **and the flag immediately preceding it**, so a verifier is never
handed an empty file it would reject.

**Exit code is the minimum contract.** `0` means "I consider this receipt
trustworthy"; non-zero means "I do not". A verifier that implements only the
envelope tier is graded on exit code alone and reported as INCOMPLETE on tier-2
vectors it gets right — except where it accepted a receipt whose claim is false,
which is FAILED.

## Optional JSON output

Emit this on stdout and the runner grades *which* checks failed, not just
whether the receipt was accepted:

```jsonc
{
  "valid": true,                  // the ENVELOPE verdict, alone
  "attestation": {
    "passed": false,
    "findings": [
      {
        "check":  "controls_enforceable",
        "tier":   "attestation",
        "passed": false,
        "detail": "constraint 1 (\"refund_fraud_check\"): type \"anomaly_check\" is not enforceable"
      }
    ]
  }
}
```

`valid` must be the envelope verdict **alone**, so a consumer can tell the two
tiers apart. Reflect both in the exit code.

Reporting findings is strictly better than exit code alone: a vector expecting
non-conformance names the check it expects to fail, and an implementation that
rejects it for a different reason has not really caught it. The runner reports
that as a failure.

## The attestation checks

An implementation is free to name its checks differently, but the corpus grades
against these identifiers.

| Check | Establishes |
|---|---|
| `policy_digest_matches` | The receipt's `policy_digest` corresponds to the supplied manifest. |
| `controls_enforceable` | Every control the manifest declares is of a type the issuer can evaluate, with a compilable pattern and an evaluable field path. |
| `controls_accounted_for` | The receipt's evaluated-constraint count covers every control the manifest declares. |
| `authorization_consistent` | An authorizing receipt reports every counted control as passed. |
| `required_inputs_present` | Every input the manifest declares `required` carries a value in the call. |
| `inputs_bound` | The receipt's `inputs_hash` binds the supplied inputs. |

### Deriving `controls_enforceable`

This is the check that catches the real failures, and it is implementation-
specific by nature: it asks whether **the issuer** could have evaluated the
control, which means the verifier needs a view of what is enforceable. Two
workable approaches:

1. **Allowlist.** The verifier knows the set of control types the issuing
   implementation supports and flags anything outside it. Simple, and adequate
   when verifier and issuer share a lineage.
2. **Static analysis of the manifest.** Reject patterns that do not compile,
   field paths using syntax the resolver has no support for (wildcards,
   aggregate function calls), timezones that do not load, thresholds with no
   bound. This catches vector 03, which an allowlist alone does not — the
   constraint type there is perfectly valid.

Vectors 02 and 03 are deliberately split so the two are graded separately.

## Number canonicalization

Receipts bind inputs by hashing a canonical encoding. Implementations must
preserve the numeric literal from the JSON document rather than normalizing
through a float:

- **Go** — `json.Decoder.UseNumber()`. The default decodes every number into
  `float64`, so `42` becomes `42.0` and the hash diverges for every
  integer-valued field.
- **Python** — `json.loads` already distinguishes `int` from `float`.
- **JavaScript** — there is no int/float distinction; follow the receipt
  format's canonicalization rules (RFC 8785 defines number output via
  ECMAScript `Number::toString`).

Vector 06 exercises this. An implementation that fails it because of numeric
handling rather than the intended `inputs_bound` mismatch has failed for the
wrong reason.

## Versioning

Vectors are append-only. An existing vector's `expect` block changes only with a
stated reason in the commit message, because implementations pin against it.
