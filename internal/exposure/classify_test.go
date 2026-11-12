package exposure

import (
	"strings"
	"testing"

	"github.com/optimuslabs-io/grokpatrol/internal/model"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		in   Response
		want model.Exposure
	}{
		{"app content", Response{Status: 200, Body: []byte("<html><title>Tiny City</title>")}, model.ExposurePublic},
		{"google sign-in", Response{Status: 200, Body: []byte("<button>Continue with Google</button>")}, model.ExposureAppSignIn},
		{"x sign-in", Response{Status: 200, Body: []byte("<button>Continue with X</button>")}, model.ExposureAppSignIn},
		{"xbox is not x", Response{Status: 200, Body: []byte("continue with xbox controller")}, model.ExposurePublic},
		{"grok refused", Response{Status: 401}, model.ExposureRestricted},
		{"not found", Response{Status: 404}, model.ExposureNotFound},
		{"gone", Response{Status: 410}, model.ExposureNotFound},
		{"cloudflare header", Response{Status: 403, CFMitigated: "challenge"}, model.ExposureUnknown},
		{"cloudflare page on 200", Response{Status: 200, Body: []byte("<title>Just a moment...</title>")}, model.ExposureUnknown},
		{"forbidden is not restricted", Response{Status: 403}, model.ExposureUnknown},
		{"redirect elsewhere", Response{Status: 302, RedirectOffHost: true}, model.ExposureUnknown},
		{"rate limited", Response{Status: 429}, model.ExposureUnknown},
		{"server error", Response{Status: 502}, model.ExposureUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got, note := Classify(c.in); got != c.want || note == "" {
				t.Errorf("Classify = %q (%q), want %q with a note", got, note, c.want)
			}
		})
	}
}

// The page body is inspected and dropped. Nothing from it may reach the note,
// which is printed and written to --json.
func TestClassifyNeverEchoesTheBody(t *testing.T) {
	const plant = "PLANTED-VALUE-7f3a9c"
	for _, status := range []int{200, 401, 403, 404, 429, 500} {
		for _, body := range []string{plant, "Continue with Google " + plant, "<title>Just a moment " + plant} {
			if _, note := Classify(Response{Status: status, Body: []byte(body)}); strings.Contains(note, plant) {
				t.Fatalf("status %d: note carried page content: %q", status, note)
			}
		}
	}
}
