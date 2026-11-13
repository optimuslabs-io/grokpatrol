#!/bin/sh
# watch-apps.sh: a desktop alert within minutes when a grok.me app opens without
# sign-in.
#
# It cannot warn before a publish. Grok Build publishes from grok.com, in the
# browser, where nothing on this machine can intercept it. Instead this runs a light
# grokpatrol-online --watch on a schedule (launchd on macOS; a crontab line you add
# elsewhere) and shows a notification when an app newly opens without sign-in, or
# newly serves a server secret with --scan-public.
#
# The grokpatrol-apps skill runs only install, status and uninstall. install and
# uninstall print what they would do and change nothing without --apply. The watch
# record and alerts stay on this machine; nothing here is read back into an agent.
set -eu

label=io.optimuslabs.grokpatrol-watch

usage() {
	cat <<'USAGE'
Usage: watch-apps.sh install   [--keyword K]... [--domain D]... [--scan-public]
                               [--interval MIN] [--bin PATH] [--dir DIR] [--apply]
       watch-apps.sh uninstall [--dir DIR] [--apply]
       watch-apps.sh status    [--dir DIR]
       watch-apps.sh run       [--keyword K]... [--domain D]... [--scan-public]
                               [--bin PATH] [--dir DIR] [--home DIR] [--no-notify]

Watch for grok.me apps that open without sign-in and show a desktop notification
when one does. Each run looks only for grok.me addresses on this machine (browser
history, Grok sessions, shell history), plus public name lists when you give org
keywords, and checks the apps that are due: new ones and those first seen in the
last day on every run, the last week hourly, older ones daily.

  install       schedule a run every --interval minutes (default 15). macOS: a
                launchd agent; elsewhere: prints a crontab line to add yourself.
                Cron supports intervals 5, 6, 10, 12, 15, 20, 30 and 60 minutes.
                Prints the plan and changes nothing without --apply.
  uninstall     stop and remove the schedule (with --apply). Keeps the record.
  status        is it scheduled, when did it last run, how many apps it watches.
  run           one run now (what the schedule calls).

  --keyword K     org keyword: 4-63 of a-z, 0-9 and '-' (repeatable). With a keyword
                  or domain, public name lists (crt.sh, urlscan.io) are asked every 6
                  hours too.
  --domain D      org domain, e.g. acme.com (repeatable)
  --scan-public   also scan public apps' scripts for keys: when an app first opens,
                  then daily (up to 9 requests per public app)
  --interval MIN  minutes between runs, 5 to 1440 on macOS; cron supports the
                  intervals listed above (install; default 15)
  --bin PATH      grokpatrol-online (default $GROKPATROL_ONLINE, else on PATH)
  --dir DIR       where the record and log live (default ~/.grokpatrol/watch)
  --home DIR      scan this home directory instead (run; for testing)
  --no-notify     print alerts on stdout instead of notifying (run; for testing)
  --apply         make the change (install, uninstall)
  -h, --help      show this help

Network per run: one unauthenticated request per due app; with keywords, crt.sh and
urlscan.io every 6 hours. API keys are not stored in the schedule.
USAGE
}

die() { printf 'watch-apps: %s\n' "$1" >&2; exit 2; }

valid_keyword() { printf '%s' "$1" | grep -Eqx '[a-z0-9][a-z0-9-]{2,61}[a-z0-9]'; }
valid_domain() {
	[ "${#1}" -le 253 ] && printf '%s' "$1" | grep -Eqx '([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}'
}

# abs prints an absolute path for an existing file.
abs() {
	case "$1" in
	/*) printf '%s\n' "$1" ;;
	*) printf '%s/%s\n' "$(cd "$(dirname "$1")" && pwd)" "$(basename "$1")" ;;
	esac
}

xml() { printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'; }

cmd="${1:-}"
case "$cmd" in
install | uninstall | status | run) shift ;;
-h | --help) usage; exit 0 ;;
"") usage >&2; exit 2 ;;
*) die "unknown command (see --help)" ;;
esac

keywords=""
domains=""
scan=""
interval=15
bin="${GROKPATROL_ONLINE:-}"
dir="$HOME/.grokpatrol/watch"
home=""
no_notify=""
apply=""
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
	--scan-public) scan=1; shift ;;
	--interval)
		[ $# -ge 2 ] || die "--interval needs a value"
		printf '%s' "$2" | grep -Eqx '[0-9]{1,4}' && [ "$2" -ge 5 ] && [ "$2" -le 1440 ] || die "--interval is minutes, 5 to 1440"
		interval=$2
		shift 2 ;;
	--bin)
		[ $# -ge 2 ] || die "--bin needs a value"
		bin=$2
		shift 2 ;;
	--dir)
		[ $# -ge 2 ] || die "--dir needs a value"
		dir=$2
		shift 2 ;;
	--home)
		[ $# -ge 2 ] || die "--home needs a value"
		[ -d "$2" ] || die "--home is not a directory"
		home=$2
		shift 2 ;;
	--no-notify) no_notify=1; shift ;;
	--apply) apply=1; shift ;;
	-h | --help) usage; exit 0 ;;
	*) die "unknown argument (see --help)" ;;
	esac
done

if [ "$cmd" = install ] && [ "$(uname -s)" != Darwin ] &&
	{ [ "$interval" -gt 60 ] || [ $((60 % interval)) -ne 0 ]; }; then
	die "cron supports intervals of 5, 6, 10, 12, 15, 20, 30 or 60 minutes"
fi

resolve_bin() {
	if [ -z "$bin" ]; then
		bin=$(command -v grokpatrol-online 2>/dev/null) || die "grokpatrol-online not found; pass --bin, set GROKPATROL_ONLINE or put it on PATH"
	fi
	[ -f "$bin" ] && [ -x "$bin" ] || die "grokpatrol-online at $bin is not an executable file"
	bin=$(abs "$bin")
}

log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" >>"$dir/watch.log"; }

lock_is_stale() {
	[ -n "$(find "$dir/lock" -maxdepth 0 -mmin +30 2>/dev/null)" ]
}

lock_identity() {
	ls -di "$dir/lock" 2>/dev/null | awk '{print $1}'
}

lock_owner() {
	cat "$dir/lock/owner" 2>/dev/null || true
}

acquire_lock() {
	if mkdir "$dir/lock" 2>/dev/null; then
		printf '%s\n' "$$" >"$dir/lock/owner"
		return 0
	fi
	if ! lock_is_stale; then
		log "previous run still going; skipped"
		return 1
	fi
	old_identity=$(lock_identity)
	old_owner=$(lock_owner)
	case "$old_owner" in
		*[!0-9]* | "")
			;;
		*)
			if kill -0 "$old_owner" 2>/dev/null; then
				log "previous run still going; skipped"
				return 1
			fi
			;;
	esac
	if ! mkdir "$dir/lock/recovery" 2>/dev/null; then
		log "another run is recovering the stale lock; skipped"
		return 1
	fi
	if [ -z "$old_identity" ] || [ "$(lock_identity)" != "$old_identity" ] ||
		[ "$(lock_owner)" != "$old_owner" ]; then
		rmdir "$dir/lock/recovery" 2>/dev/null || true
		log "watch lock changed during stale-lock recovery; skipped"
		return 1
	fi
	stale_lock="$dir/lock.stale.$$"
	if [ -e "$stale_lock" ] || [ -L "$stale_lock" ] ||
		! mv "$dir/lock" "$stale_lock" 2>/dev/null; then
		log "watch lock changed during stale-lock recovery; skipped"
		return 1
	fi
	if ! mkdir "$dir/lock" 2>/dev/null; then
		rm -rf "$stale_lock"
		log "another run acquired the watch lock; skipped"
		return 1
	fi
	printf '%s\n' "$$" >"$dir/lock/owner"
	rm -rf "$stale_lock" 2>/dev/null || true
}

release_lock() {
	if [ "$(lock_owner)" = "$$" ]; then
		rm -rf "$dir/lock" "$dir/state.json.new" "$dir/stderr.tmp"
	fi
}

notify() {
	log "ALERT $1: $2"
	if [ -n "$no_notify" ]; then
		printf '%s: %s\n' "$1" "$2"
		return 0
	fi
	case "$(uname -s)" in
	Darwin)
		/usr/bin/osascript -e 'on run argv' \
			-e 'display notification (item 2 of argv) with title (item 1 of argv) sound name "Basso"' \
			-e 'end run' "$1" "$2" >/dev/null 2>&1 || log "could not show a notification" ;;
	*)
		if command -v notify-send >/dev/null 2>&1; then
			notify-send -u critical -a grokpatrol "$1" "$2" || log "could not show a notification"
		fi ;;
	esac
}

do_run() {
	resolve_bin
	mkdir -p "$dir"
	chmod 700 "$dir"
	# Recovery is claimed inside the stale lock. Its identity and owner are rechecked
	# before removal, so another run cannot replace it between the check and cleanup.
	if ! acquire_lock; then
		return 0
	fi
	trap 'release_lock' EXIT INT TERM

	set -- --watch "$dir/state.json" --timeout 10m
	for k in $keywords; do set -- "$@" --org-keyword "$k"; done
	for d in $domains; do set -- "$@" --org-domain "$d"; done
	discovering=""
	if [ -n "$keywords$domains" ] &&
		{ [ ! -f "$dir/discovered-at" ] || [ -n "$(find "$dir/discovered-at" -mmin +360 2>/dev/null)" ]; }; then
		set -- "$@" --discover
		discovering=1
	fi
	[ -z "$scan" ] || set -- "$@" --scan-public
	[ -z "$home" ] || set -- "$@" --home "$home"

	if "$bin" "$@" >"$dir/state.json.new" 2>"$dir/stderr.tmp"; then
		rc=0
	else
		rc=$?
	fi
	if [ "$rc" = 0 ] && [ -s "$dir/state.json.new" ]; then
		mv "$dir/state.json.new" "$dir/state.json"
		[ -z "$discovering" ] || touch "$dir/discovered-at"
	else
		log "grokpatrol-online exited $rc; the watch record was not changed"
	fi
	tab=$(printf '\t')
	while IFS= read -r line; do
		case "$line" in
		"alert$tab"*)
			rest=${line#alert"$tab"}
			notify "${rest%%"$tab"*}" "${rest#*"$tab"}" ;;
		*) log "$line" ;;
		esac
	done <"$dir/stderr.tmp"
	# Keep the log small: it is a record of alerts and failures, not an archive.
	if [ "$(wc -l <"$dir/watch.log")" -gt 2000 ]; then
		tail -n 1000 "$dir/watch.log" >"$dir/watch.log.tmp" && mv "$dir/watch.log.tmp" "$dir/watch.log"
	fi
	return "$rc"
}

# run_args prints the arguments the schedule passes to `run`, one per line.
run_args() {
	printf '%s\n' run --bin "$bin" --dir "$dir"
	for k in $keywords; do printf '%s\n' --keyword "$k"; done
	for d in $domains; do printf '%s\n' --domain "$d"; done
	[ -z "$scan" ] || printf '%s\n' --scan-public
}

shell_quote() {
	printf "'"
	printf '%s' "$1" | sed "s/'/'\\\\''/g"
	printf "'"
}

cron_quote() {
	shell_quote "$1" | sed 's/%/\\%/g'
}

cron_args() {
	run_args | while IFS= read -r arg; do
		cron_quote "$arg"
		printf ' '
	done
}

do_install() {
	resolve_bin
	self=$(abs "$0")
	installed="$dir/watch-apps.sh"
	if [ "$(uname -s)" != Darwin ]; then
		line="*/$interval * * * * /bin/sh $(cron_quote "$installed") $(cron_args)"
		if [ -z "$apply" ]; then
			printf 'Plan: copy this script to %s, then you add this line with `crontab -e`:\n  %s\nRe-run with --apply to copy the script.\n' "$installed" "$line"
			return 0
		fi
		mkdir -p "$dir" && chmod 700 "$dir"
		cp "$self" "$installed" && chmod 700 "$installed"
		printf 'Copied the script to %s. Add this line with `crontab -e`:\n  %s\n' "$installed" "$line"
		return 0
	fi
	plist="$HOME/Library/LaunchAgents/$label.plist"
	if [ -z "$apply" ]; then
		printf 'Plan:\n  copy this script to %s\n  write %s: every %s minutes, %s\n  load it with launchctl (it runs once straight away and sends one summary notification)\nRe-run with --apply to do it.\n' \
			"$installed" "$plist" "$interval" "/bin/sh $installed $(run_args | tr '\n' ' ')"
		return 0
	fi
	mkdir -p "$dir" "$HOME/Library/LaunchAgents"
	chmod 700 "$dir"
	[ "$self" = "$installed" ] || { cp "$self" "$installed" && chmod 700 "$installed"; }
	{
		printf '<?xml version="1.0" encoding="UTF-8"?>\n'
		printf '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
		printf '<plist version="1.0">\n<dict>\n'
		printf '  <key>Label</key><string>%s</string>\n' "$label"
		printf '  <key>ProgramArguments</key>\n  <array>\n'
		printf '    <string>/bin/sh</string>\n    <string>%s</string>\n' "$(xml "$installed")"
		run_args | while IFS= read -r a; do printf '    <string>%s</string>\n' "$(xml "$a")"; done
		printf '  </array>\n'
		printf '  <key>StartInterval</key><integer>%s</integer>\n' "$((interval * 60))"
		printf '  <key>RunAtLoad</key><true/>\n'
		printf '  <key>ProcessType</key><string>Background</string>\n'
		printf '  <key>LowPriorityIO</key><true/>\n'
		printf '  <key>StandardOutPath</key><string>%s</string>\n' "$(xml "$dir/launchd.log")"
		printf '  <key>StandardErrorPath</key><string>%s</string>\n' "$(xml "$dir/launchd.log")"
		printf '</dict>\n</plist>\n'
	} >"$plist.tmp"
	mv "$plist.tmp" "$plist"
	uid=$(id -u)
	launchctl bootout "gui/$uid/$label" 2>/dev/null || true
	launchctl bootstrap "gui/$uid" "$plist"
	printf 'Installed: runs every %s minutes and once now. Expect one summary notification shortly.\n' "$interval"
	printf 'macOS may ask whether Script Editor can show notifications; allow it, or alerts only reach %s.\n' "$dir/watch.log"
}

do_uninstall() {
	plist="$HOME/Library/LaunchAgents/$label.plist"
	if [ "$(uname -s)" != Darwin ]; then
		printf 'Remove the grokpatrol watch line with `crontab -e`. The record and log are in %s.\n' "$dir"
		return 0
	fi
	if [ -z "$apply" ]; then
		printf 'Plan: unload %s and delete %s. The record and log in %s are kept.\nRe-run with --apply to do it.\n' "$label" "$plist" "$dir"
		return 0
	fi
	launchctl bootout "gui/$(id -u)/$label" 2>/dev/null || true
	rm -f "$plist"
	printf 'Uninstalled. The record and log are still in %s; delete that folder to remove them.\n' "$dir"
}

do_status() {
	if [ "$(uname -s)" = Darwin ]; then
		if launchctl print "gui/$(id -u)/$label" >/dev/null 2>&1; then
			echo "scheduled: yes (launchd $label)"
		else
			echo "scheduled: no"
		fi
	else
		echo "scheduled: check your crontab (crontab -l)"
	fi
	if [ -f "$dir/state.json" ]; then
		printf 'last run: %s\n' "$(grep -m1 '"checked_at"' "$dir/state.json" | sed 's/.*: *"\(.*\)".*/\1/')"
		printf 'apps watched: %s\n' "$(grep -c '"host":' "$dir/state.json" || true)"
		printf 'open without sign-in: %s\n' "$(grep -c '"public_since":' "$dir/state.json" || true)"
	else
		echo "last run: never"
	fi
	if [ -f "$dir/watch.log" ]; then
		echo "recent log:"
		tail -n 5 "$dir/watch.log" | sed 's/^/  /'
	fi
}

case "$cmd" in
run) do_run ;;
install) do_install ;;
uninstall) do_uninstall ;;
status) do_status ;;
esac
