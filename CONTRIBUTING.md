# Contributing

Vectors from other implementations are the point of this repo, **including ones
this corpus would fail**. If you have a receipt that is signed correctly and says
something untrue in a way these seven vectors miss, that is the most valuable
contribution possible here.

## Adding a vector

1. Generate it from a **real signed receipt**, not a hand-written blob. A corpus
   of synthetic receipts drifts from what implementations actually emit, and then
   it is testing a fiction.
2. Use a throwaway key and a non-production issuer. Vectors are public forever.
3. State `why` — the failure it guards against, in a sentence an implementer can
   act on. "Tests the policy digest" is not a reason; "a genuine receipt and a
   genuine manifest that are not about each other" is.
4. A vector expecting `attestation_conformant: false` **must** name the check it
   expects to fail. Without it, an implementation can pass by rejecting the
   receipt for an unrelated reason and nobody learns anything.
5. Run `go test ./...` — the corpus has its own well-formedness tests.

## What does not belong here

- Vectors that test a specific product's behaviour rather than a property of the
  format.
- Anything requiring network access to grade.
- Receipts carrying real identities, real keys, or real customer data.

## Governance

Maintained by [Duvera](https://duvera.ai) today. The corpus is meant to outlive
any one vendor's implementation; if it becomes useful to the ecosystem, moving it
to a neutral home is a feature, not a loss.
