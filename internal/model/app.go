package model

import "time"

// PublishedApp is a Grok Build app address (<name>.grok.me) found in a file on this
// host: browser history, a Grok CLI session, shell history.
//
// Host is the one file-derived string in the report that is not a path, and it is
// allowed for the same reason the gs:// destinations in Evidence.Locator are: it is
// an ADDRESS, not content. The apps detector only ever emits a Host that passed a
// strict hostname check (one DNS label under grok.me), so nothing else a file
// contains can travel through this field.
//
// Seen on this machine is not the same as owned by this user: browser history
// records every app the user OPENED, including other people's. The report says so.
type PublishedApp struct {
	Host string     `json:"host"`
	Seen []Evidence `json:"seen"` // where the address was found on this host; Path + Note only

	// Source says how the app was first found: AppSourceLocal (a file on this host),
	// AppSourcePassiveDNS (a public name list, matched to this org by MatchedBy) or
	// AppSourceWebSearch (a URL a web search returned).
	Source string `json:"source"`
	// Sources names every public source that also listed the app: "crt.sh",
	// "urlscan", "otx", "grok-search", "web-search". Empty when none were queried.
	Sources []string `json:"sources,omitempty"`
	// MatchedBy is tool-authored prose naming the rule that tied a public-source-only
	// name to this org: an org keyword in the name, or a custom domain under an org
	// domain. Empty for apps found on this host.
	MatchedBy string `json:"matched_by,omitempty"`
	// PointsTo is the grok.me name a custom domain's CNAME points at. Set only when
	// Host is a custom domain rather than a grok.me name.
	PointsTo string `json:"points_to,omitempty"`
	// FirstSeen and LastSeen are the earliest and latest dates any public source saw
	// the name (UTC): certificate issue (crt.sh), scan (urlscan), resolution (OTX).
	FirstSeen *time.Time `json:"first_seen,omitempty"`
	LastSeen  *time.Time `json:"last_seen,omitempty"`

	// Exposure is set only by the opt-in online check (--check-exposure, in the
	// grokpatrol-online build). Empty means nobody asked the network, which is the
	// default and the only possible state in the standard, network-free build.
	Exposure     Exposure `json:"exposure,omitempty"`
	ExposureNote string   `json:"exposure_note,omitempty"` // tool-authored prose, never the page body
	HTTPStatus   int      `json:"http_status,omitempty"`

	// Secrets is set only by --scan-public: the content rules that matched in what a
	// stranger is served (the home page and its same-host scripts). Rule ids and
	// asset paths only, never a value, excerpt or hash.
	Secrets []AppSecret `json:"secrets,omitempty"`
	// SecretScan is tool-authored prose saying what the secret scan read, or why it
	// did not run for this app. Empty when --scan-public was not asked for.
	SecretScan string `json:"secret_scan,omitempty"`
}

// AppSecret is one content rule that matched in a public app.
type AppSecret struct {
	Rule string     `json:"rule"` // gitleaks rule id, or "service-role-jwt"
	Kind SecretKind `json:"kind"`
	// Asset is the path of the file it was found in, "/" for the home page. Only
	// paths of letters, digits and ._~/- are ever fetched, so this is never prose.
	Asset string `json:"asset"`
}

// SecretKind separates keys that must never reach a browser from keys built to.
type SecretKind string

const (
	// SecretServer: a server-side secret (an AI provider key, a cloud or payment
	// secret, a Supabase service_role key). Anyone who opened the app has it.
	SecretServer SecretKind = "server"
	// SecretBrowser: a key or client id made to ship in web pages (a Firebase web
	// key, a Mapbox public token). Safe only if it is restricted by its provider.
	SecretBrowser SecretKind = "browser"
)

const (
	AppSourceLocal      = "local"
	AppSourcePassiveDNS = "passive_dns"
	AppSourceWebSearch  = "web_search"
)

// Exposure is what one unauthenticated request for an app's home page showed.
type Exposure string

const (
	// ExposurePublic: the app's own content loaded with no sign-in. Anyone who has
	// or finds the address can open it, and passive DNS makes the address findable.
	ExposurePublic Exposure = "public"
	// ExposureAppSignIn: the page loaded, but it is the app's own sign-in screen.
	// Not the same as private: the app decides who gets in, and an app that lets
	// any Google or X account through is still open to anyone.
	ExposureAppSignIn Exposure = "app_sign_in"
	// ExposureRestricted: Grok itself refused (401): "Only you" or "Invited users".
	ExposureRestricted Exposure = "restricted"
	// ExposureNotFound: 404. Never published, unpublished, or taken down.
	ExposureNotFound Exposure = "not_found"
	// ExposureUnknown: blocked, rate-limited, redirected elsewhere, or the request
	// failed. Never read as safe.
	ExposureUnknown Exposure = "unknown"
)
