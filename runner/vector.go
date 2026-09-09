package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Tier names the level of guarantee a check establishes.
type Tier string

const (
	TierEnvelope    Tier = "envelope"
	TierAttestation Tier = "attestation"
)

// Finding is one attestation check's outcome, as reported by a verifier.
type Finding struct {
	Check  string `json:"check"`
	Tier   Tier   `json:"tier"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

// Result is a verifier's attestation verdict.
type Result struct {
	Passed   bool      `json:"passed"`
	Findings []Finding `json:"findings"`
}

// Vector is one conformance case: a receipt, the artifacts needed to judge it,
// and the verdict a conformant verifier must reach. Self-contained JSON so an
// implementation in any language can run the corpus with no dependency on this
// repo or any product.
type Vector struct {
	ID    string `json:"id"`
	Tier  Tier   `json:"tier"`
	Title string `json:"title"`
	// Why this case exists — the failure it guards against, in a sentence an
	// implementer can act on.
	Why string `json:"why"`

	Receipt  string          `json:"receipt"`            // compact JWS
	JWKS     json.RawMessage `json:"jwks"`               // the only trust anchor
	Manifest string          `json:"manifest,omitempty"` // capability YAML, verbatim
	Inputs   json.RawMessage `json:"inputs,omitempty"`   // the call's inputs

	Expect Expectation `json:"expect"`
}

// Expectation is the verdict a conformant implementation must reach. The two
// tiers are graded separately: an implementation may legitimately support only
// the envelope, and should report that rather than guess.
type Expectation struct {
	EnvelopeValid         bool     `json:"envelope_valid"`
	AttestationConformant *bool    `json:"attestation_conformant,omitempty"`
	FailingChecks         []string `json:"failing_checks,omitempty"`
}

// LoadVectors reads every *.json vector in dir, sorted by id for stable output.
func LoadVectors(dir string) ([]Vector, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	var out []Vector
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", p, err)
		}
		var v Vector
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", p, err)
		}
		if v.ID == "" {
			return nil, fmt.Errorf("%s: vector has no id", p)
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Grade compares an implementation's outcome against the vector's expectation
// and returns the reasons it does not conform (empty means it does).
func (v Vector) Grade(envelopeValid bool, attestation *Result) []string {
	var problems []string
	if envelopeValid != v.Expect.EnvelopeValid {
		problems = append(problems, fmt.Sprintf(
			"envelope: expected valid=%v, got valid=%v", v.Expect.EnvelopeValid, envelopeValid))
	}
	if v.Expect.AttestationConformant == nil {
		return problems
	}
	if attestation == nil {
		problems = append(problems, "attestation: no verdict reported (tier 2 not implemented)")
		return problems
	}
	if attestation.Passed != *v.Expect.AttestationConformant {
		problems = append(problems, fmt.Sprintf(
			"attestation: expected conformant=%v, got conformant=%v",
			*v.Expect.AttestationConformant, attestation.Passed))
	}
	// Naming the right check matters: an implementation that fails a vector for
	// the wrong reason has not really caught it.
	failed := map[string]bool{}
	for _, f := range attestation.Findings {
		if !f.Passed {
			failed[f.Check] = true
		}
	}
	for _, want := range v.Expect.FailingChecks {
		if !failed[want] {
			problems = append(problems, fmt.Sprintf("attestation: expected check %q to fail, it did not", want))
		}
	}
	return problems
}
