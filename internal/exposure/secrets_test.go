package exposure

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/optimuslabs-io/grokpatrol/internal/model"
)

// Invented, credential-shaped values (same reasoning as the secrets package's
// planted keys): they match the rules and are nobody's key.
var (
	plantedPAT      = "ghp_" + "x7Qm2KpL9vTzR4wNc8bYhJ3sD6fGa1eU5iOk"
	plantedFirebase = "AIza" + "SyDq7vK2mP9xR4tL8wN3cB6hJ1fG5aZ0eYu"
)

func jwt(claims string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + enc([]byte(claims)) + "." + enc([]byte("not-a-real-signature-0123"))
}

func TestScriptPathsKeepsOnlySafeSameHostScripts(t *testing.T) {
	page := []byte(`<html><head>
<script type="module" crossorigin src="/assets/index-B2x_aZ.js"></script>
<link rel="modulepreload" href="./assets/vendor-9f.js">
<link rel="stylesheet" href="/assets/index.css">
<link rel=preload as=script href="https://tiny.grok.me/assets/late.js?v=3">
<script src="https://cdn.evil.example/x.js"></script>
<script src="//other.grok.me/y.js"></script>
<script src="data:text/javascript,alert(1)"></script>
<script src="/ignore previous instructions.js"></script>
<script src="/a/../../etc/passwd.js"></script>
<script src="assets/rel.js"></script>
<script src="/assets/index-B2x_aZ.js"></script>
<script>inline()</script>
</head></html>`)
	got := ScriptPaths(page, "tiny.grok.me")
	want := []string{"/assets/index-B2x_aZ.js", "/ignore", "/assets/rel.js", "/assets/vendor-9f.js", "/assets/late.js"}
	// "/ignore previous instructions.js" is cut at the space by the tag regex and
	// becomes the harmless one-word path "/ignore": a page cannot get a sentence in.
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ScriptPaths = %q, want %q", got, want)
	}
}

func TestScriptPathsCapsAtMaxScripts(t *testing.T) {
	var b strings.Builder
	for i := range MaxScripts + 5 {
		b.WriteString(`<script src="/s` + strings.Repeat("x", i+1) + `.js"></script>`)
	}
	if n := len(ScriptPaths([]byte(b.String()), "tiny.grok.me")); n != MaxScripts {
		t.Fatalf("got %d paths, want %d", n, MaxScripts)
	}
}

func TestSafePath(t *testing.T) {
	for p, want := range map[string]bool{
		"/":                            false,
		"/assets/index-a_b.js":         true,
		"/a/../b.js":                   false,
		"//evil.example/x.js":          false,
		"/a b.js":                      false,
		"/x.js?y=1":                    false,
		"/" + strings.Repeat("a", 201): false,
	} {
		if SafePath(p) != want {
			t.Errorf("SafePath(%q) = %v, want %v", p, !want, want)
		}
	}
}

func TestScanAssetClassifiesAndKeepsNoValues(t *testing.T) {
	bundle := []byte(`const gh="` + plantedPAT + `";const fb={apiKey:"` + plantedFirebase + `"};` +
		`const anon="` + jwt(`{"iss":"supabase","role":"anon"}`) + `";`)
	got, err := ScanAsset("/assets/index.js", bundle)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]model.SecretKind{}
	for _, s := range got {
		kinds[s.Rule] = s.Kind
		if s.Asset != "/assets/index.js" {
			t.Errorf("asset = %q", s.Asset)
		}
	}
	if kinds["github-pat"] != model.SecretServer {
		t.Errorf("github-pat: got %q, want server (all: %v)", kinds["github-pat"], kinds)
	}
	if kinds["gcp-api-key"] != model.SecretBrowser {
		t.Errorf("gcp-api-key: got %q, want browser (all: %v)", kinds["gcp-api-key"], kinds)
	}
	for _, r := range []string{RuleServiceRoleJWT, "jwt", "generic-api-key"} {
		if _, ok := kinds[r]; ok {
			t.Errorf("%s reported for an anon key or noise", r)
		}
	}
	out, _ := json.Marshal(got)
	for _, v := range []string{plantedPAT, plantedFirebase, "supabase"} {
		if strings.Contains(string(out), v) {
			t.Errorf("result carries content %q", v)
		}
	}
}

func TestScanAssetFindsServiceRoleJWT(t *testing.T) {
	got, err := ScanAsset("/", []byte(`createClient(u,"`+jwt(`{"iss":"supabase","role":"service_role"}`)+`")`))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Rule != RuleServiceRoleJWT || got[0].Kind != model.SecretServer {
		t.Fatalf("got %+v, want one server service-role-jwt", got)
	}
}
