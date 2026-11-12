package exposure

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/optimuslabs-io/grokpatrol/internal/detect/secrets"
	"github.com/optimuslabs-io/grokpatrol/internal/model"
)

// Limits on the secret scan of one public app: what a stranger's browser loads
// first, not a crawl.
const (
	MaxScripts     = 8
	MaxScriptBytes = 4 << 20
)

// skippedRules are content rules that are noise in a web bundle: generic-api-key
// fires on minified identifiers, and a bare JWT in a Supabase app is almost always
// the anon key. JWTs are judged by their role claim instead (serviceRoleJWT).
var skippedRules = map[string]bool{
	"generic-api-key": true, "jwt": true, "jwt-base64": true,
	"pkcs12-file": true, "kubernetes-secret-yaml": true,
}

// browserRules match keys and client ids that providers design to ship in web
// pages. They matter only if the key is unrestricted, so they are reported apart
// from server secrets.
var browserRules = map[string]bool{
	"gcp-api-key": true, "algolia-api-key": true, "mapbox-api-token": true,
	"new-relic-browser-api-token": true, "contentful-delivery-api-token": true,
	"gitlab-feature-flag-client-token": true, "flutterwave-public-key": true,
	"lob-pub-api-key": true, "mailgun-pub-key": true,
	"adobe-client-id": true, "asana-client-id": true, "bitbucket-client-id": true,
	"discord-client-id": true, "linkedin-client-id": true, "looker-client-id": true,
	"messagebird-client-id": true, "plaid-client-id": true, "sendbird-access-id": true,
	"sumologic-access-id": true, "new-relic-user-api-id": true,
}

// RuleServiceRoleJWT names a JWT whose role claim is service_role: a Supabase key
// that bypasses row-level security.
const RuleServiceRoleJWT = "service-role-jwt"

// ScanAsset scans one fetched file in memory and returns what matched. asset is
// the path it came from ("/" for the home page) and is recorded as is; callers
// pass only paths that passed SafePath. The data is not kept.
func ScanAsset(asset string, data []byte) ([]model.AppSecret, error) {
	name := "bundle.js"
	if asset == "/" {
		name = "index.html"
	}
	ids, err := secrets.ScanBytes(name, data)
	if err != nil {
		return nil, err
	}
	var out []model.AppSecret
	for _, id := range ids {
		if skippedRules[id] {
			continue
		}
		kind := model.SecretServer
		if browserRules[id] {
			kind = model.SecretBrowser
		}
		out = append(out, model.AppSecret{Rule: id, Kind: kind, Asset: asset})
	}
	if serviceRoleJWT(data) {
		out = append(out, model.AppSecret{Rule: RuleServiceRoleJWT, Kind: model.SecretServer, Asset: asset})
	}
	return out, nil
}

var jwtRE = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.(eyJ[A-Za-z0-9_-]{8,})\.[A-Za-z0-9_-]{8,}`)

// serviceRoleJWT reports whether data holds a JWT whose payload claims
// "role":"service_role". Only the claim is read; the token is not kept.
func serviceRoleJWT(data []byte) bool {
	for _, m := range jwtRE.FindAllSubmatch(data, 64) {
		payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(string(m[1]), "="))
		if err != nil {
			continue
		}
		var claims struct {
			Role string `json:"role"`
		}
		if json.Unmarshal(payload, &claims) == nil && claims.Role == "service_role" {
			return true
		}
	}
	return false
}

var (
	scriptTagRE = regexp.MustCompile(`(?is)<script\b[^>]*?\bsrc\s*=\s*["']?([^"'\s>]+)`)
	linkTagRE   = regexp.MustCompile(`(?is)<link\b[^>]*>`)
	hrefRE      = regexp.MustCompile(`(?is)\bhref\s*=\s*["']?([^"'\s>]+)`)
	relRE       = regexp.MustCompile(`(?is)\brel\s*=\s*["']?(modulepreload|preload)\b`)
	safePathRE  = regexp.MustCompile(`^/[A-Za-z0-9._~/-]{1,200}$`)
)

// ScriptPaths returns the same-host script paths a home page loads (script src,
// and link rel=modulepreload or rel=preload), in page order, at most MaxScripts.
// host is the app's host; a reference to any other host is dropped, and so is
// any path that fails SafePath. The page is untrusted, so nothing it says can
// name another destination.
func ScriptPaths(page []byte, host string) []string {
	var refs []string
	for _, m := range scriptTagRE.FindAllSubmatch(page, -1) {
		refs = append(refs, string(m[1]))
	}
	for _, tag := range linkTagRE.FindAll(page, -1) {
		if !relRE.Match(tag) {
			continue
		}
		if m := hrefRE.FindSubmatch(tag); m != nil && strings.HasSuffix(strings.ToLower(pathOnly(string(m[1]))), ".js") {
			refs = append(refs, string(m[1]))
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, r := range refs {
		p, ok := sameHostPath(r, host)
		if !ok || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
		if len(out) == MaxScripts {
			break
		}
	}
	return out
}

// sameHostPath resolves a reference from the home page ("/") to a path on host.
func sameHostPath(ref, host string) (string, bool) {
	ref = strings.TrimSpace(ref)
	lower := strings.ToLower(ref)
	switch {
	case strings.HasPrefix(lower, "https://"), strings.HasPrefix(lower, "//"):
		rest := ref[strings.Index(ref, "//")+2:]
		h, p, _ := strings.Cut(rest, "/")
		if !strings.EqualFold(h, host) {
			return "", false
		}
		ref = "/" + p
	case strings.Contains(ref, ":"):
		return "", false // http:, data:, javascript: and the like
	case strings.HasPrefix(ref, "./"):
		ref = ref[1:]
	case !strings.HasPrefix(ref, "/"):
		ref = "/" + ref
	}
	ref = pathOnly(ref)
	return ref, SafePath(ref)
}

func pathOnly(ref string) string {
	if i := strings.IndexAny(ref, "?#"); i >= 0 {
		return ref[:i]
	}
	return ref
}

// SafePath reports whether p is a plain absolute path: letters, digits and
// ._~/- only, no "..", at most 200 characters. Only such paths are fetched or
// recorded, so a page cannot smuggle prose into the report through a path.
func SafePath(p string) bool {
	return safePathRE.MatchString(p) && !strings.Contains(p, "..") && !strings.Contains(p, "//")
}
