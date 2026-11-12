// Package exposure decides whether a grok.me app opens for a stranger.
//
// This file is the decision only: it turns what one unauthenticated request saw into
// an Exposure, and it has no network code, so it is built and tested in every build.
// The request itself lives in check.go, which is compiled only with -tags online and
// never reaches the standard grokpatrol binary (make verify-deps proves that).
package exposure

import (
	"bytes"

	"github.com/optimuslabs-io/grokpatrol/internal/model"
)

// Response is what the classifier is allowed to know about a reply. The body is
// inspected for a handful of fixed phrases and then dropped: no part of it is stored,
// returned or printed, the same rule grokpatrol applies to secret values.
type Response struct {
	Status          int
	CFMitigated     string // Cloudflare's cf-mitigated header ("challenge" on a bot check)
	RedirectOffHost bool   // the app redirected to a different host, which we did not follow
	Body            []byte // at most the first maxBody bytes
}

// HeaderCFMitigated is the header Cloudflare sets on a challenge, in canonical form.
// Written out rather than computed: net/textproto would link net into every build.
const HeaderCFMitigated = "Cf-Mitigated"

// signInPhrases are the buttons on a Grok Build app's own sign-in screen. Claroc's
// research (Nov 2026) describes that screen as offering Google and X.
var signInPhrases = [][]byte{
	[]byte("continue with google"),
	[]byte("continue with x"),
	[]byte("sign in with google"),
	[]byte("sign in with x"),
}

// challengePhrases mark a Cloudflare interstitial rather than the app.
var challengePhrases = [][]byte{
	[]byte("<title>just a moment"),
	[]byte("challenge-platform"),
}

// Classify maps one response to an Exposure and a tool-authored note. Anything it
// cannot place is Unknown, never Restricted: a check that failed is not a check
// that passed.
func Classify(r Response) (model.Exposure, string) {
	body := bytes.ToLower(r.Body)
	switch {
	case r.CFMitigated != "" || containsAny(body, challengePhrases):
		return model.ExposureUnknown, "blocked by Cloudflare's bot check; open it in a private browser window to see what a stranger gets"
	case r.RedirectOffHost:
		return model.ExposureUnknown, "redirected to another site (possibly a sign-in page); open it in a private browser window to confirm"
	case r.Status == 200 && hasSignIn(body):
		return model.ExposureAppSignIn, "opens to the app's own sign-in screen; check who that sign-in lets in, since some Grok apps accept any Google or X account"
	case r.Status == 200:
		return model.ExposurePublic, "opened with no sign-in; anyone with the address can use it, and passive DNS makes the address findable. " +
			"An app that draws its sign-in screen in JavaScript can look open here, so confirm in a private browser window"
	case r.Status == 401:
		return model.ExposureRestricted, "Grok refused an unsigned visitor (Only you / Invited users)"
	case r.Status == 404 || r.Status == 410:
		return model.ExposureNotFound, "not found: never published, unpublished, or taken down"
	case r.Status == 429:
		return model.ExposureUnknown, "rate limited; re-run later"
	default:
		return model.ExposureUnknown, "unexpected response; open it in a private browser window to confirm"
	}
}

func containsAny(b []byte, phrases [][]byte) bool {
	for _, p := range phrases {
		if bytes.Contains(b, p) {
			return true
		}
	}
	return false
}

// hasSignIn matches a sign-in phrase as whole words, so "continue with xbox" is not
// read as an X sign-in button.
func hasSignIn(b []byte) bool {
	for _, p := range signInPhrases {
		for i := 0; ; {
			j := bytes.Index(b[i:], p)
			if j < 0 {
				break
			}
			end := i + j + len(p)
			if end >= len(b) || !isWordByte(b[end]) {
				return true
			}
			i = end
		}
	}
	return false
}

func isWordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_'
}
