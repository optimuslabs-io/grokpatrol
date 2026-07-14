package secrets

import (
	"path"
	"strings"
)

// Secret classes are matched on FILENAME ONLY. No file is ever opened, no blob is
// ever read, no value is ever matched or printed.
//
// That is sufficient for the job: the deliverable is a rotation checklist, and
// "prod/.env was in the uploaded object set" tells you exactly what to rotate
// without this tool ever having to look at the credential itself.
const (
	ClassDotenv     = "dotenv"
	ClassPrivateKey = "private-key"
	ClassKeystore   = "keystore"
	ClassCloudCred  = "cloud-credential"
	ClassRegistry   = "package-registry"
	ClassIaC        = "iac-secret"
	ClassKube       = "kubeconfig"
	ClassGeneric    = "generic-secret"
)

// Classify returns the secret class for a repo-relative path, or "" if the file
// is not secret-shaped.
func Classify(p string) string {
	p = strings.ToLower(path.Clean(strings.ReplaceAll(p, "\\", "/")))
	base := path.Base(p)
	ext := path.Ext(base)

	// Templates and examples are the single biggest source of noise in a report
	// like this, and a false "rotate this" costs the reader trust in the real ones.
	if isExample(base) {
		return ""
	}

	switch {
	case base == ".env" || strings.HasPrefix(base, ".env.") || strings.HasSuffix(base, ".env"):
		return ClassDotenv

	case base == "id_rsa" || base == "id_dsa" || base == "id_ecdsa" || base == "id_ed25519":
		return ClassPrivateKey
	case ext == ".pem" || ext == ".key" || ext == ".ppk":
		if strings.HasSuffix(base, ".pub") {
			return ""
		}
		return ClassPrivateKey

	case ext == ".p12" || ext == ".pfx" || ext == ".jks" || ext == ".keystore":
		return ClassKeystore

	case base == "credentials.json" || base == "client_secret.json" ||
		strings.HasPrefix(base, "service-account") && ext == ".json" ||
		strings.HasPrefix(base, "serviceaccount") && ext == ".json" ||
		strings.HasPrefix(base, "client_secret") && ext == ".json":
		return ClassCloudCred
	case strings.HasSuffix(p, ".aws/credentials") || strings.HasSuffix(p, ".gcp/credentials.json"):
		return ClassCloudCred

	case base == ".npmrc" || base == ".pypirc" || base == ".netrc" || base == "_netrc" ||
		strings.HasSuffix(p, ".gem/credentials"):
		return ClassRegistry

	// tfstate is worth calling out specifically: it famously embeds the plaintext
	// values of every secret the plan touched.
	case base == "terraform.tfvars" || strings.HasSuffix(base, ".auto.tfvars") ||
		ext == ".tfstate" || strings.HasSuffix(base, ".tfstate.backup"):
		return ClassIaC

	case base == "kubeconfig" || ext == ".kubeconfig" || strings.HasSuffix(p, ".kube/config"):
		return ClassKube

	case base == ".htpasswd" || base == "htpasswd":
		return ClassGeneric
	case strings.Contains(base, "secret"):
		// secrets.yaml, app-secrets.json, latest-secrets.yaml, sealed-secret.yaml.
		// Matched anywhere in the name rather than only as a prefix -- but never for
		// source files, or internal/secrets/secrets.go would be a "credential".
		if isCode(ext) {
			return ""
		}
		return ClassGeneric
	}
	return ""
}

// noiseWords mark a file as a template or fixture rather than a live credential.
var noiseWords = map[string]bool{
	"example": true, "examples": true, "sample": true, "samples": true,
	"template": true, "templates": true, "dist": true, "tpl": true, "defaults": true,
	"dummy": true, "fake": true, "mock": true, "fixture": true, "fixtures": true,
	"test": true, "tests": true, "testing": true,
}

// isExample reports whether a filename is a template rather than a real secret.
//
// It matches whole WORDS, not substrings. A substring match here is a
// false-negative machine, and a false negative is the worst failure this tool has:
// strings.Contains(".env.latest", "test") is true -- "la-TEST" -- so a naive
// version silently drops a live .env.latest from the rotation checklist, with no
// error and no missing-row warning. Same for resample.pem, contest.env,
// attestation.key. Over-reporting a template costs the reader five seconds;
// under-reporting a credential costs them the credential.
func isExample(base string) bool {
	for _, w := range strings.FieldsFunc(base, func(r rune) bool {
		return r == '.' || r == '-' || r == '_'
	}) {
		if noiseWords[w] {
			return true
		}
	}
	return false
}

func isCode(ext string) bool {
	switch ext {
	case ".go", ".rs", ".py", ".js", ".ts", ".java", ".rb", ".c", ".h", ".cpp", ".cs", ".php", ".md", ".txt":
		return true
	}
	return false
}
