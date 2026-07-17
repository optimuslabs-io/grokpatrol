package secrets

// These tests pin the transcribed gitleaks corpus and the ported engine.
// Planted "secrets" below are invented values in a TEST file -- this binary is
// never shipped, so the marker/literal rules for shipped sources do not apply.

import (
	"math"
	"slices"
	"strings"
	"testing"
)

// TestAllRulesCompile is the transcription guard: every regex in the generated
// table must compile with stdlib RE2. A bad vendored refresh fails here, at
// test time, not at first --full-secrets-search run.
func TestAllRulesCompile(t *testing.T) {
	rs, err := compileRules(contentRules, globalAllow)
	if err != nil {
		t.Fatalf("compileRules: %v", err)
	}
	if got, want := len(rs.rules), 222; got != want {
		t.Fatalf("rule count = %d, want %d (gitleaks %s shipped 222 rules; a refresh must update this pin consciously)", got, want, gitleaksRulesVersion)
	}
	for _, r := range rs.rules {
		if r.id == "" {
			t.Fatal("rule with empty id")
		}
		if r.re == nil && r.pathRE == nil {
			t.Fatalf("rule %s has neither content nor path regex", r.id)
		}
	}
}

func scanOne(t *testing.T, path, content string) []string {
	t.Helper()
	rs, err := compiledRules()
	if err != nil {
		t.Fatalf("compiledRules: %v", err)
	}
	if rs.pathSkipped(path) {
		return nil
	}
	return rs.scan(path, []byte(content))
}

func TestContentScanFindsPlantedSecrets(t *testing.T) {
	cases := []struct {
		name, path, content, wantRule string
	}{
		{"aws key", "config/prod.yaml", "aws_access_key_id: " + plantedAWSKey + "\n", "aws-access-token"},
		{"github pat", "deploy.sh", "export TOKEN=" + plantedGitHubPAT + "\n", "github-pat"},
		{"private key", "old/backup.txt", "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAr8xJ4tGq2eZ7dK9mW3pV5bN1cX6hS0fL2uY8oT4iR7wQ9aB3\nMIIEowIBAAKCAQEAr8xJ4tGq2eZ7dK9mW3pV5bN1cX6hS0fL2uY8oT4iR7wQ9aB3\n-----END RSA PRIVATE KEY-----\n", "private-key"},
		{"generic api key", "app/settings.py", `API_KEY = "zX9kQ2mP7wL4nR8tY3vB"` + "\n", "generic-api-key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := scanOne(t, tc.path, tc.content)
			if !slices.Contains(got, tc.wantRule) {
				t.Fatalf("scan(%s) = %v, want it to include %q", tc.path, got, tc.wantRule)
			}
		})
	}
}

// TestContentScanSuppressesKnownNoise pins the allowlist/stopword/entropy
// machinery: each of these is a string that MATCHES some rule's regex and must
// still not be reported. Every false "rotate this" costs the reader trust in
// the real ones.
func TestContentScanSuppressesKnownNoise(t *testing.T) {
	cases := []struct {
		name, path, content string
		rule                string // the rule that must NOT fire
	}{
		// aws-access-token allowlists `.+EXAMPLE$` -- AWS's own documented key.
		{"aws docs example", "README.adoc", "key: AKIAIOSFODNN7EXAMPLE\n", "aws-access-token"},
		// generic-api-key stopwords: value contains "example".
		{"stopword secret", "app/config.rb", `api_key = "test-example-key-12345"` + "\n", "generic-api-key"},
		// generic-api-key first allowlist: pure-word secrets `^[a-zA-Z_.-]+$`.
		{"pure word value", "app/config.rb", `password = "changemeplease"` + "\n", "generic-api-key"},
		// entropy gate: repeated characters have ~zero entropy.
		{"low entropy", "app/config.rb", `api_key = "aaaaaaaaaaaaaaaaaaaa"` + "\n", "generic-api-key"},
		// line-target allowlist: Dockerfile secret mounts are references, not values.
		{"docker mount", "Dockerfile", "RUN --mount=type=secret,id=api_key,target=/run/x cargo build\n", "generic-api-key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := scanOne(t, tc.path, tc.content); slices.Contains(got, tc.rule) {
				t.Fatalf("scan reported %q for known-noise input %q", tc.rule, tc.name)
			}
		})
	}
}

// TestGlobalPathAllowlistSkipsLockfiles: gitleaks never scans lockfiles,
// vendored trees, or images; neither do we.
func TestGlobalPathAllowlistSkipsLockfiles(t *testing.T) {
	rs, err := compiledRules()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"package-lock.json", "web/yarn.lock", "vendor/modules.txt", "img/logo.png", "go.sum"} {
		if !rs.pathSkipped(p) {
			t.Errorf("pathSkipped(%q) = false, want true", p)
		}
	}
	for _, p := range []string{"config/prod.yaml", ".env", "main.go"} {
		if rs.pathSkipped(p) {
			t.Errorf("pathSkipped(%q) = true, want false", p)
		}
	}
}

// TestShannonEntropyMatchesGitleaks pins the exact formula (per-rune counts
// over BYTE length, gitleaks' own quirk): change the math and every threshold
// in the imported corpus silently re-tunes.
func TestShannonEntropyMatchesGitleaks(t *testing.T) {
	cases := []struct {
		in   string
		want float64
	}{
		{"", 0},
		{"aaaa", 0},
		{"ab", 1},
		{"abcd", 2},
		// Hand-computed: A and H thrice, P and M twice, ten singletons, len 20.
		{plantedAWSKey, 2*0.15*math.Log2(1/0.15) + 2*0.1*math.Log2(1/0.1) + 10*0.05*math.Log2(1/0.05)},
		// The gitleaks quirk this test exists to pin: "é" is ONE rune but TWO
		// bytes, so its frequency is 1/len("é") = 0.5, not 1.0. Entropy 0.5, not 0.
		{"é", 0.5},
	}
	for _, tc := range cases {
		if got := shannonEntropy(tc.in); math.Abs(got-tc.want) > 1e-9 {
			t.Errorf("shannonEntropy(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestPathOnlyRule: pkcs12-file has no content regex; the filename is the hit.
func TestPathOnlyRule(t *testing.T) {
	got := scanOne(t, "certs/prod.p12", "\x30\x82binarygoo")
	if !slices.Contains(got, "pkcs12-file") {
		t.Fatalf("scan(certs/prod.p12) = %v, want pkcs12-file", got)
	}
}

// TestScanReturnsOnlyRuleIDs is the leak guard at the engine boundary: every
// string scan() returns must be a rule id from the table, so a matched value
// can never ride out through its return path.
func TestScanReturnsOnlyRuleIDs(t *testing.T) {
	ids := map[string]bool{}
	for _, r := range contentRules {
		ids[r.ID] = true
	}
	otherGHPAT := "ghp_" + "F4kEv4lUe0000111122223333444455aa" // distinct from plantedGitHubPAT, same shape reasoning
	content := "aws_key=" + plantedAWSKey + " " + otherGHPAT + "\n" +
		`API_KEY="zX9kQ2mP7wL4nR8tY3vB"` + "\n"
	for _, got := range scanOne(t, "leaky.txt", content) {
		if !ids[got] {
			t.Fatalf("scan returned %q, which is not a rule id", got)
		}
		if strings.Contains(content, got) {
			t.Fatalf("scan returned %q, which appears in the scanned content", got)
		}
	}
}
