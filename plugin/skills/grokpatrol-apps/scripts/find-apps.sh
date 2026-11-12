#!/bin/sh
# find-apps.sh: the only way the grokpatrol-apps skill runs grokpatrol-online.
#
# The agent driving the skill reads web search results, which are untrusted: a page
# can carry text meant to steer it. So the agent never composes the command line.
# It passes org keywords and domains (which must come from the user) as flags and
# the search-result URLs on stdin; this script validates them, builds the command,
# keeps its files in a private mktemp directory, and prints only --apps-only JSON,
# which carries no repositories or secret locations.
set -eu

usage() {
	cat <<'USAGE'
Usage: find-apps.sh [--keyword K]... [--domain D]... [--grok-search]
                   [--scan-public [--scan-keyword-matches]] [--home DIR] < urls

Find Grok Build apps (*.grok.me) tied to an organisation and check whether each
opens without sign-in. Prints grokpatrol-online's --apps-only JSON on stdout.

  --keyword K     org keyword: 4-63 characters of a-z, 0-9 and '-', not starting or ending with '-' (repeatable)
  --domain D      org domain, e.g. acme.com (repeatable); also a keyword source
  --grok-search   add xAI web and X search (needs $XAI_API_KEY; bills xAI API credits)
  --scan-public   scan public apps' home page and same-host scripts in memory for keys
                  (apps seen on this machine or under --domain only)
  --scan-keyword-matches
                  with --scan-public, also scan apps tied to the org only by a keyword or a
                  search result (they may be someone else's)
  --home DIR      scan this home directory instead of the user's (for testing)
  -h, --help      show this help

stdin: URLs or hostnames returned by web search, one per line (may be empty).
Binary: $GROKPATROL_ONLINE, else grokpatrol-online on PATH.
Network: crt.sh, urlscan.io, OTX (with $OTX_API_KEY), and one unauthenticated
request per app found (up to 9 per public app with --scan-public). Nothing is written outside a temporary directory that is
removed on exit.
USAGE
}

die() { printf 'find-apps: %s\n' "$1" >&2; exit 2; }

valid_keyword() { printf '%s' "$1" | grep -Eqx '[a-z0-9][a-z0-9-]{2,61}[a-z0-9]'; }
valid_domain() {
	[ "${#1}" -le 253 ] && printf '%s' "$1" | grep -Eqx '([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}'
}

keywords=""
domains=""
grok=""
scan=""
leads=""
home=""
while [ $# -gt 0 ]; do
	case "$1" in
	--keyword)
		[ $# -ge 2 ] || die "--keyword needs a value"
		k=$(printf '%s' "$2" | tr 'A-Z' 'a-z')
		valid_keyword "$k" || die "invalid --keyword (4-63 of a-z, 0-9, '-'; no leading or trailing '-')"
		keywords="$keywords $k"
		shift 2 ;;
	--domain)
		[ $# -ge 2 ] || die "--domain needs a value"
		d=$(printf '%s' "$2" | tr 'A-Z' 'a-z' | sed 's/\.$//')
		valid_domain "$d" || die "invalid --domain"
		domains="$domains $d"
		shift 2 ;;
	--grok-search) grok=1; shift ;;
	--scan-public) scan=1; shift ;;
	--scan-keyword-matches) leads=1; shift ;;
	--home)
		[ $# -ge 2 ] || die "--home needs a value"
		[ -d "$2" ] || die "--home is not a directory"
		home="$2"
		shift 2 ;;
	-h|--help) usage; exit 0 ;;
	*) die "unknown argument (see --help)" ;;
	esac
done
[ -n "$keywords$domains" ] || die "give at least one --keyword or --domain"
[ -z "$leads" ] || [ -n "$scan" ] || die "--scan-keyword-matches needs --scan-public"

bin="${GROKPATROL_ONLINE:-}"
if [ -z "$bin" ]; then
	bin=$(command -v grokpatrol-online 2>/dev/null) || die "grokpatrol-online not found; set GROKPATROL_ONLINE or put it on PATH"
fi
[ -x "$bin" ] || die "grokpatrol-online at $bin is not executable"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/grokpatrol-apps.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT TERM
hosts="$tmp/hosts.txt"
if [ -t 0 ]; then
	: > "$hosts"
else
	head -c 4194304 > "$hosts"
fi

set -- --json --apps-only --discover --check-exposure --app-hosts "$hosts"
for k in $keywords; do set -- "$@" --org-keyword "$k"; done
for d in $domains; do set -- "$@" --org-domain "$d"; done
[ -z "$grok" ] || set -- "$@" --grok-search
[ -z "$scan" ] || set -- "$@" --scan-public
[ -z "$leads" ] || set -- "$@" --scan-keyword-matches
[ -z "$home" ] || set -- "$@" --home "$home"

printf 'find-apps: keywords:%s; domains:%s; grok search: %s; secret scan: %s\n' \
	"${keywords:- none}" "${domains:- none}" "$([ -n "$grok" ] && echo on || echo off)" \
	"$([ -n "$leads" ] && echo 'on, keyword matches too' || { [ -n "$scan" ] && echo on || echo off; })" >&2
"$bin" "$@"
