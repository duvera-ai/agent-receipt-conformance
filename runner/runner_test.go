package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const corpusDir = "../vectors"

// stubVerifier writes an executable that prints body and exits with code. It
// stands in for a third-party verifier so the grading logic — which decides
// whether an implementation misled its user — is tested without depending on
// any real one.
func stubVerifier(t *testing.T, body string, code int) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "verifier.sh")
	script := "#!/bin/sh\n"
	if body != "" {
		script += "cat <<'JSONEOF'\n" + body + "\nJSONEOF\n"
	}
	script += "exit " + string(rune('0'+code)) + "\n"
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func vectorByID(t *testing.T, id string) Vector {
	t.Helper()
	vs, err := LoadVectors(corpusDir)
	if err != nil {
		t.Fatalf("loading corpus: %v", err)
	}
	for _, v := range vs {
		if v.ID == id {
			return v
		}
	}
	t.Fatalf("vector %q not in corpus", id)
	return Vector{}
}

// The headline judgement: a verifier that checks only the signature and accepts
// a receipt whose claim is false must FAIL, and say why in terms of the
// consequence to a caller.
func TestEnvelopeOnlyVerifierFailsAFalseReceipt(t *testing.T) {
	v := vectorByID(t, "02-attestation-control-never-ran")
	sv := stubVerifier(t, `{"valid":true}`, 0)

	got := gradeOne(v, sv+" {jwks} {manifest} {inputs} {receipt}", t.TempDir())
	if got.Status != "fail" {
		t.Fatalf("want fail, got %q (%v)", got.Status, got.Problems)
	}
	if len(got.Problems) == 0 || !strings.Contains(got.Problems[0], "never ran") {
		t.Errorf("the failure should explain the consequence, got %v", got.Problems)
	}
}

// The same verifier on the vector where everything genuinely holds is honest but
// incomplete — it must not be marked failed for giving the right answer.
func TestEnvelopeOnlyIsIncompleteNotWrongOnAGoodReceipt(t *testing.T) {
	v := vectorByID(t, "01-envelope-valid-attestation-conformant")
	sv := stubVerifier(t, `{"valid":true}`, 0)

	if got := gradeOne(v, sv+" {jwks} {manifest} {inputs} {receipt}", t.TempDir()); got.Status != "incomplete" {
		t.Fatalf("want incomplete, got %q (%v)", got.Status, got.Problems)
	}
}

func TestTier1VectorPassesWithoutAttestation(t *testing.T) {
	v := vectorByID(t, "07-envelope-tampered-payload")
	sv := stubVerifier(t, `{"valid":false}`, 1)

	if got := gradeOne(v, sv+" {jwks} {receipt}", t.TempDir()); got.Status != "pass" {
		t.Fatalf("want pass, got %q (%v)", got.Status, got.Problems)
	}
}

// Rejecting for the wrong reason is not catching it.
func TestAttestationGradedOnTheSpecificCheck(t *testing.T) {
	v := vectorByID(t, "02-attestation-control-never-ran")
	tmpl := " {jwks} {manifest} {inputs} {receipt}"

	right := mustJSON(t, map[string]any{"valid": true, "attestation": Result{
		Passed: false, Findings: []Finding{{Check: "controls_enforceable", Tier: TierAttestation}},
	}})
	if got := gradeOne(v, stubVerifier(t, right, 1)+tmpl, t.TempDir()); got.Status != "pass" {
		t.Fatalf("failing the right check should pass: %q %v", got.Status, got.Problems)
	}

	wrong := mustJSON(t, map[string]any{"valid": true, "attestation": Result{
		Passed: false, Findings: []Finding{{Check: "inputs_bound", Tier: TierAttestation}},
	}})
	if got := gradeOne(v, stubVerifier(t, wrong, 1)+tmpl, t.TempDir()); got.Status != "fail" {
		t.Fatalf("failing the wrong check must not count as catching it: %q", got.Status)
	}
}

func TestFalseRejectionOnAGoodReceiptFails(t *testing.T) {
	v := vectorByID(t, "01-envelope-valid-attestation-conformant")
	sv := stubVerifier(t, `{"valid":false}`, 1)

	if got := gradeOne(v, sv+" {jwks} {manifest} {inputs} {receipt}", t.TempDir()); got.Status != "fail" {
		t.Fatalf("want fail, got %q", got.Status)
	}
}

// A vector with no manifest must not leave a dangling flag pointing at an empty
// file the verifier would reject.
func TestDropFlagRemovesTheFlagAndItsValue(t *testing.T) {
	got := dropFlag("verify --jwks /j --policy /m --json /r", "/m")
	if strings.Contains(got, "--policy") || strings.Contains(got, "/m") {
		t.Errorf("flag not fully removed: %q", got)
	}
	if !strings.Contains(got, "--jwks /j") || !strings.Contains(got, "--json /r") {
		t.Errorf("dropped too much: %q", got)
	}
}

func TestCorpusIsWellFormed(t *testing.T) {
	vs, err := LoadVectors(corpusDir)
	if err != nil {
		t.Fatalf("loading corpus: %v", err)
	}
	if len(vs) < 5 {
		t.Fatalf("corpus is suspiciously small: %d", len(vs))
	}
	seen, tier2 := map[string]bool{}, 0
	for _, v := range vs {
		if seen[v.ID] {
			t.Errorf("duplicate vector id %q", v.ID)
		}
		seen[v.ID] = true
		if v.Why == "" {
			t.Errorf("%s: a vector with no stated reason cannot be acted on by an implementer", v.ID)
		}
		if v.Receipt == "" || len(v.JWKS) == 0 {
			t.Errorf("%s: must carry a receipt and a JWKS", v.ID)
		}
		if v.Expect.AttestationConformant != nil {
			tier2++
			if !*v.Expect.AttestationConformant && len(v.Expect.FailingChecks) == 0 {
				t.Errorf("%s: a non-conformant vector must name the check it expects to fail, "+
					"or an implementation can pass it for the wrong reason", v.ID)
			}
		}
	}
	if tier2 == 0 {
		t.Error("corpus has no attestation vectors — it is just another envelope suite")
	}
}

// If an envelope-only verifier could pass the whole corpus, the tier-2 vectors
// are not testing anything.
func TestCorpusDiscriminates(t *testing.T) {
	vs, err := LoadVectors(corpusDir)
	if err != nil {
		t.Fatal(err)
	}
	caught := 0
	for _, v := range vs {
		if len(v.Grade(v.Expect.EnvelopeValid, nil)) > 0 {
			caught++
		}
	}
	if caught == 0 {
		t.Fatal("envelope-only verification passes every vector — the corpus measures nothing")
	}
	t.Logf("envelope-only verification leaves %d/%d vectors ungraded or wrong", caught, len(vs))
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
