# Agent-receipt conformance

**A receipt can be cryptographically perfect and still be false.**

Every agent-receipt specification converging in 2026 — [APort / Open Agent
Passport](https://aport.io/spec/), [Microsoft's Agent Governance
Toolkit](https://microsoft.github.io/agent-governance-toolkit/proposals/verifiable-compliance-receipts/),
the [ASQAV](https://datatracker.ietf.org/doc/draft-marques-asqav-compliance-receipts/)
and [ACTA](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/)
IETF drafts, Signet, Pipelock, Agent Passport System — has converged on the same
definition of *verifiable*:

> An Ed25519 key signed these RFC 8785 canonical bytes.

That convergence is real progress, and it is the right foundation. This corpus
exists to build the next storey on it.

## What a receipt should establish

An agent takes an action. A receipt says the action was authorized under a
policy, and names the controls that were evaluated. Someone later — an auditor,
a regulator, a counterparty, a downstream service — needs to decide whether to
believe it.

A signature answers one question: *did the issuer commit to these bytes?*

It leaves the more important one open: **was the thing the bytes say actually
so?** A receipt reporting `constraints_passed: 8/8` is making a claim about
eight controls. Suppose one of them names a risk model the issuer never
implemented, so it silently evaluated to "pass". Suppose another is written
against a field path that always resolves to nothing, so it is skipped on every
call. Suppose a third reads an input the caller simply omitted.

In all three the signature is valid. The canonicalization is correct. The key is
the right key. And the receipt is not true.

None of these are exotic. They are the natural shape of a policy evaluator: an
unknown control type falls through to "not our problem", an absent field is
"nothing to check", and both read as success. The gap between *signed* and *true*
is where an evidence system either earns its name or doesn't.

## Two tiers

| Tier | Establishes |
|---|---|
| **Envelope** | A key the issuer controls signed exactly these bytes. |
| **Attestation** | The receipt's *claim* about policy evaluation is supported by the policy it names. |

Attestation conformance is checkable **offline by a third party** from two
artifacts an auditor can obtain — the receipt, and the published capability
manifest it names by digest. It requires no access to, and no trust in, the
issuer's infrastructure. That is the point: an issuer marking its own homework is
not evidence.

### The checks

| Check | Question it answers |
|---|---|
| `policy_digest_matches` | Was this receipt issued under the policy I am holding? Without it, every check below is about a policy that was never applied. |
| `controls_enforceable` | Could the controls it counted actually run — enforceable types, compilable patterns, evaluable field paths? |
| `controls_accounted_for` | Does the receipt account for every control the policy declares, or only a subset? |
| `authorization_consistent` | It authorizes the action; does it also report that every control it counted passed? |
| `required_inputs_present` | Did the call supply the inputs the policy declares required? A control reading an absent field is skipped, not satisfied. |
| `inputs_bound` | Is this receipt evidence about *this* call, or a different one? |

## Run it

```bash
go run ./runner --verifier "your-verifier --jwks {jwks} --policy {manifest} {receipt}"
```

`{receipt}`, `{jwks}`, `{manifest}`, `{inputs}` are replaced with paths to each
vector's artifacts. Your verifier must exit `0` when it considers the receipt
trustworthy and non-zero otherwise. If it also emits the JSON shape in
[SPEC.md](./SPEC.md), the runner grades *which* checks failed — an implementation
that rejects a vector for the wrong reason has not really caught it.

## Grading

- **CONFORMANT** — both tiers, every vector.
- **ENVELOPE-ONLY** — signatures check out; no attestation verdict. Honest, and
  the state of the art today.
- **NON-CONFORMANT** — reported a receipt as trustworthy whose claim does not
  hold.

The distinction between the last two is deliberate and it is the whole design.
Not implementing attestation is a gap. Telling a caller that a control which
never ran was satisfied is a different thing, and the corpus names it
differently.

An envelope-only verifier scores **1 pass, 5 fail, 1 incomplete**.

## The corpus

Seven vectors in [`vectors/`](./vectors), each self-contained JSON — receipt,
JWKS, capability manifest, inputs — so an implementation in any language can run
them with no dependency on this repo or any product.

| Vector | What it catches |
|---|---|
| `01-envelope-valid-attestation-conformant` | Baseline: everything holds; must not be flagged. |
| `02-attestation-control-never-ran` | Perfect signature; one control names a model the issuer does not implement. |
| `03-attestation-dead-field-path` | Subtler than 02 — the constraint *type* is valid; the path resolves to nothing forever. |
| `04-attestation-required-input-omitted` | The call omitted the field the cap is written against, so the cap never fired. |
| `05-attestation-wrong-policy` | Genuine receipt, genuine manifest, not about each other. |
| `06-attestation-inputs-not-bound` | A valid receipt offered as evidence about a different call. |
| `07-envelope-tampered-payload` | Tier-1 baseline. |

Every vector is generated from a **real signed receipt**, not a hand-written
blob, so the corpus cannot drift from what implementations actually emit.

### The canonicalization trap

Vector 06 doubles as an interop test. Go's `encoding/json` decodes every JSON
number into `float64`, so the literal `42` canonicalizes as `42.0` and the
`inputs_hash` stops binding for **every integer-valued field** — silently, with a
valid signature. Decode with `json.Decoder.UseNumber()`, or your language's
equivalent literal-preserving mode. An implementation that fails vector 06 for
*this* reason has failed it for the wrong reason, which the runner reports.

## Scope, stated plainly

- Attestation conformance establishes that the controls a receipt counted **could
  have run**, and that the receipt **names the policy supplied**. It does not
  prove the issuer executed them faithfully — nothing offline can. It closes the
  gap between *signed* and *true*, not between *true* and *certain*.
- It requires the capability manifest. A receipt alone cannot be
  attestation-checked, which is itself a finding: an ecosystem that publishes
  receipts without publishing the policies they name has not published evidence.
- The corpus grades a **verifier**, not a gateway.

## Contributing

New vectors welcome, including ones this corpus would fail. If you have a receipt
that is signed correctly and says something untrue in a way these seven vectors
miss, that is the most valuable contribution possible here. See
[CONTRIBUTING.md](./CONTRIBUTING.md).

Every vector must state the failure it guards against, and a vector expecting
non-conformance must name the check it expects to fail — otherwise an
implementation can pass it by accident.

Apache-2.0. Maintained by [Duvera](https://duvera.ai); the corpus is meant to
outlive any one vendor's implementation, and pull requests from other
implementations are the point.
