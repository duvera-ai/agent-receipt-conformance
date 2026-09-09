// Command runner grades a receipt verifier — any verifier, in any language —
// against the agent-receipt conformance corpus.
//
// Two tiers:
//
//	ENVELOPE     a key the issuer controls signed exactly these bytes.
//	             Every receipt implementation in the field already does this.
//
//	ATTESTATION  the receipt's CLAIM about policy evaluation is supported by
//	             the policy it names. Almost nothing does this, and it is where
//	             real receipts fail: a control of a type the issuer never
//	             implemented, a field path that resolves to nothing, a required
//	             input the call omitted. Each produces a receipt with a perfect
//	             signature attesting that N of N controls passed.
//
// An implementation supporting only tier 1 is INCOMPLETE, not FAILED —
// envelope verification is honest work, it just is not the whole claim. An
// implementation that reports a tier-2 vector as fully valid is FAILED, because
// it told its user a false receipt was trustworthy.
//
// Usage:
//
//	go run ./runner --verifier "my-verifier --jwks {jwks} --policy {manifest} {receipt}"
//	go run ./runner --json
//
// The verifier command is a template. Placeholders are replaced with paths to
// temp files holding each vector's artifacts:
//
//	{receipt}   the compact receipt
//	{jwks}      the JWKS, the only trust anchor
//	{manifest}  the capability manifest (flag dropped when a vector has none)
//	{inputs}    the call's inputs (flag dropped when a vector has none)
//
// Exit 0 means "this receipt is trustworthy"; non-zero means it is not. Emit
// the JSON shape in SPEC.md on stdout and the runner also grades which specific
// checks failed.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type vectorReport struct {
	ID       string   `json:"id"`
	Tier     string   `json:"tier"`
	Title    string   `json:"title"`
	Status   string   `json:"status"` // pass | fail | incomplete
	Problems []string `json:"problems,omitempty"`
}

type suiteReport struct {
	Verifier   string         `json:"verifier"`
	Total      int            `json:"total"`
	Passed     int            `json:"passed"`
	Failed     int            `json:"failed"`
	Incomplete int            `json:"incomplete"`
	Verdict    string         `json:"verdict"` // conformant | envelope-only | non-conformant
	Vectors    []vectorReport `json:"vectors"`
}

func main() {
	corpus := flag.String("corpus", defaultCorpus(), "directory of conformance vectors")
	verifier := flag.String("verifier", "", "verifier command template ({receipt} {jwks} {manifest} {inputs})")
	jsonOut := flag.Bool("json", false, "emit a machine-readable report")
	flag.Parse()

	if *verifier == "" {
		fail("--verifier is required, e.g.\n  --verifier \"my-verifier --jwks {jwks} --policy {manifest} {receipt}\"")
	}

	vectors, err := LoadVectors(*corpus)
	if err != nil {
		fail("loading corpus: %v", err)
	}
	if len(vectors) == 0 {
		fail("no vectors found in %s", *corpus)
	}

	work, err := os.MkdirTemp("", "agent-receipt-conformance-")
	if err != nil {
		fail("temp dir: %v", err)
	}
	defer os.RemoveAll(work)

	rep := suiteReport{Verifier: *verifier, Total: len(vectors)}
	for _, v := range vectors {
		vr := gradeOne(v, *verifier, work)
		switch vr.Status {
		case "pass":
			rep.Passed++
		case "incomplete":
			rep.Incomplete++
		default:
			rep.Failed++
		}
		rep.Vectors = append(rep.Vectors, vr)
	}
	switch {
	case rep.Failed > 0:
		rep.Verdict = "non-conformant"
	case rep.Incomplete > 0:
		rep.Verdict = "envelope-only"
	default:
		rep.Verdict = "conformant"
	}

	if *jsonOut {
		b, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(b))
	} else {
		printHuman(rep)
	}
	if rep.Failed > 0 {
		os.Exit(1)
	}
}

func gradeOne(v Vector, tmpl, work string) vectorReport {
	vr := vectorReport{ID: v.ID, Tier: string(v.Tier), Title: v.Title}

	dir := filepath.Join(work, v.ID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		vr.Status, vr.Problems = "fail", []string{err.Error()}
		return vr
	}
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		_ = os.WriteFile(p, data, 0o644)
		return p
	}
	receiptPath := write("receipt.jwt", []byte(v.Receipt))
	jwksPath := write("jwks.json", v.JWKS)
	manifestPath := write("manifest.yaml", []byte(v.Manifest))
	inputsPath := write("inputs.json", v.Inputs)

	cmdline := tmpl
	for ph, val := range map[string]string{
		"{receipt}": receiptPath, "{jwks}": jwksPath,
		"{manifest}": manifestPath, "{inputs}": inputsPath,
	} {
		cmdline = strings.ReplaceAll(cmdline, ph, val)
	}
	// A vector with no manifest cannot be graded for attestation; drop the flag
	// rather than hand the verifier an empty file it will reject.
	if v.Manifest == "" {
		cmdline = dropFlag(cmdline, manifestPath)
	}
	if len(v.Inputs) == 0 {
		cmdline = dropFlag(cmdline, inputsPath)
	}

	fields := strings.Fields(cmdline)
	cmd := exec.Command(fields[0], fields[1:]...)
	// Provide the receipt on stdin too, for verifiers that read it that way.
	if f, err := os.Open(receiptPath); err == nil {
		defer f.Close()
		cmd.Stdin = f
	}
	out, runErr := cmd.Output()
	acceptedIt := runErr == nil // exit 0 = "this receipt is trustworthy"

	var parsed struct {
		Valid       bool    `json:"valid"`
		Attestation *Result `json:"attestation"`
	}
	envelopeValid := acceptedIt
	var attestation *Result
	if json.Unmarshal(out, &parsed) == nil {
		envelopeValid = parsed.Valid
		attestation = parsed.Attestation
	}

	// Tier-1 vector, or an implementation that reported a tier-2 verdict:
	// grade against the expectation directly.
	if v.Expect.AttestationConformant == nil || attestation != nil {
		if problems := v.Grade(envelopeValid, attestation); len(problems) > 0 {
			vr.Status, vr.Problems = "fail", problems
		} else {
			vr.Status = "pass"
		}
		return vr
	}

	// Tier-2 vector, no attestation verdict. The distinction that matters is not
	// "did it implement tier 2" but "did it mislead its user".
	switch {
	case !*v.Expect.AttestationConformant && acceptedIt:
		vr.Status = "fail"
		vr.Problems = []string{
			"reported this receipt as trustworthy. Its signature is valid and its claim is not — " +
				"a caller acting on this verdict acts on a control that never ran",
		}
	case envelopeValid != v.Expect.EnvelopeValid:
		vr.Status, vr.Problems = "fail", v.Grade(envelopeValid, nil)
	default:
		vr.Status = "incomplete"
		vr.Problems = []string{"envelope verdict correct; no attestation verdict reported (tier 2 not implemented)"}
	}
	return vr
}

// dropFlag removes the flag whose value is path, e.g. "--policy /tmp/x" — the
// flag name is whatever token precedes the path, so this works for any
// verifier's spelling.
func dropFlag(cmdline, path string) string {
	fields := strings.Fields(cmdline)
	var out []string
	for i := 0; i < len(fields); i++ {
		if fields[i] == path {
			// Drop the preceding token too when it looks like a flag.
			if len(out) > 0 && strings.HasPrefix(out[len(out)-1], "-") {
				out = out[:len(out)-1]
			}
			continue
		}
		out = append(out, fields[i])
	}
	return strings.Join(out, " ")
}

func printHuman(r suiteReport) {
	fmt.Printf("\nAgent-receipt conformance — %d vectors\n", r.Total)
	fmt.Printf("verifier: %s\n\n", r.Verifier)
	for _, v := range r.Vectors {
		mark := map[string]string{"pass": "PASS", "fail": "FAIL", "incomplete": "INCP"}[v.Status]
		fmt.Printf("  %-4s [%-11s] %s\n", mark, v.Tier, v.ID)
		if v.Status != "pass" {
			fmt.Printf("       %s\n", v.Title)
			for _, p := range v.Problems {
				fmt.Printf("       -> %s\n", p)
			}
		}
	}
	fmt.Println()
	switch r.Verdict {
	case "conformant":
		fmt.Printf("CONFORMANT — %d/%d, both tiers.\n", r.Passed, r.Total)
		fmt.Println("This verifier establishes that a receipt was signed AND that what it says is supported.")
	case "envelope-only":
		fmt.Printf("ENVELOPE-ONLY — %d passed, %d incomplete.\n", r.Passed, r.Incomplete)
		fmt.Println("Signatures are checked. Nothing establishes that the controls the receipt")
		fmt.Println("counted were capable of running, so a false receipt still reads as valid.")
	default:
		fmt.Printf("NON-CONFORMANT — %d passed, %d failed, %d incomplete.\n", r.Passed, r.Failed, r.Incomplete)
	}
	fmt.Println()
}

func defaultCorpus() string {
	for _, p := range []string{"vectors", "../vectors"} {
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			return p
		}
	}
	return "vectors"
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "conformance: "+format+"\n", args...)
	os.Exit(2)
}
