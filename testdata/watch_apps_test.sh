#!/bin/sh
# Tests for plugin/skills/grokpatrol-apps/scripts/watch-apps.sh, run by
# `make plugin-check`. A stand-in for grokpatrol-online records its arguments and
# prints a fixed record and alert, so no network or real scan is involved.
set -eu

script="$(cd "$(dirname "$0")/.." && pwd)/plugin/skills/grokpatrol-apps/scripts/watch-apps.sh"
work=$(mktemp -d "${TMPDIR:-/tmp}/watch-apps-test.XXXXXX")
trap 'rm -rf "$work"' EXIT

fail() { echo "FAIL: watch-apps.sh: $1"; exit 1; }

fake="$work/grokpatrol-online"
cat >"$fake" <<'FAKE'
#!/bin/sh
printf '%s\n' "$@" >>"$FAKE_ARGS"
[ -z "${FAKE_FAIL:-}" ] || { echo "boom" >&2; exit 1; }
[ -z "${FAKE_SLEEP:-}" ] || sleep "$FAKE_SLEEP"
printf '{"schema":"grokpatrol-watch/1","checked_at":"2026-11-12T09:00:00Z","apps":[{"host":"alpha-one.grok.me","public_since":"2026-11-12T09:00:00Z"}]}\n'
printf 'alert\tPublic grok.me app\talpha-one.grok.me opens without sign-in.\n' >&2
printf 'watch: 1 app, 1 checked, 1 alert, 0 errors\n' >&2
FAKE
chmod +x "$fake"
export FAKE_ARGS="$work/args"
dir="$work/state"

# A run passes --watch, shows the alert, saves the record and asks public sources once.
out=$(sh "$script" run --bin "$fake" --dir "$dir" --keyword acmepay --no-notify)
[ "$out" = "Public grok.me app: alpha-one.grok.me opens without sign-in." ] || fail "alert not shown: $out"
grep -qx -- "--watch" "$FAKE_ARGS" || fail "--watch not passed"
grep -qx -- "--discover" "$FAKE_ARGS" || fail "--discover not passed on the first run"
grep -q '"alpha-one.grok.me"' "$dir/state.json" || fail "record not saved"
grep -q 'ALERT Public grok.me app' "$dir/watch.log" || fail "alert not logged"
[ ! -e "$dir/lock" ] || fail "lock left behind"
mode=$(stat -f %Lp "$dir" 2>/dev/null) || mode=$(stat -c %a "$dir")
[ "$mode" = 700 ] || fail "record dir is not private"

# The next run does not ask public sources again within 6 hours.
: >"$FAKE_ARGS"
sh "$script" run --bin "$fake" --dir "$dir" --keyword acmepay --no-notify >/dev/null
! grep -qx -- "--discover" "$FAKE_ARGS" || fail "--discover repeated within 6 hours"

# Without keywords, public sources are never asked.
: >"$FAKE_ARGS"
sh "$script" run --bin "$fake" --dir "$work/local-only" --no-notify >/dev/null
! grep -qx -- "--discover" "$FAKE_ARGS" || fail "--discover without keywords"

# A failed run leaves the record as it was.
before=$(cat "$dir/state.json")
if FAKE_FAIL=1 sh "$script" run --bin "$fake" --dir "$dir" --no-notify >/dev/null; then
	fail "a failed run exited 0"
fi
[ "$(cat "$dir/state.json")" = "$before" ] || fail "a failed run changed the record"
grep -q 'exited 1; the watch record was not changed' "$dir/watch.log" || fail "failure not logged"

# A run that is still going (fresh lock) is not overlapped.
mkdir "$dir/lock"
: >"$FAKE_ARGS"
sh "$script" run --bin "$fake" --dir "$dir" --no-notify >/dev/null
[ ! -s "$FAKE_ARGS" ] || fail "ran while another run held the lock"
rmdir "$dir/lock"

# Two contenders recover one stale lock without starting overlapping runs.
stale="$work/stale"
mkdir -p "$stale/lock"
touch -t 200001010000 "$stale/lock"
: >"$FAKE_ARGS"
FAKE_SLEEP=1 sh "$script" run --bin "$fake" --dir "$stale" --no-notify >/dev/null 2>&1 &
first=$!
FAKE_SLEEP=1 sh "$script" run --bin "$fake" --dir "$stale" --no-notify >/dev/null 2>&1 &
second=$!
wait "$first" || fail "first stale-lock run failed"
wait "$second" || fail "second stale-lock run failed"
[ "$(grep -xc -- "--watch" "$FAKE_ARGS")" = 1 ] || fail "stale-lock recovery started overlapping runs"
[ ! -e "$stale/lock" ] || fail "stale-lock recovery left a lock behind"

# install and uninstall change nothing without --apply.
HOME="$work/home" sh "$script" install --bin "$fake" --dir "$work/inst" --keyword acmepay >"$work/plan"
grep -q 'Re-run with --apply' "$work/plan" || fail "install did not print a plan"
[ ! -e "$work/inst" ] && [ ! -e "$work/home/Library" ] || fail "install wrote without --apply"
if [ "$(uname -s)" != Darwin ]; then
	for bad_interval in 45 120; do
		if sh "$script" install --bin "$fake" --dir "$work/inst" --interval "$bad_interval" >/dev/null 2>&1; then
			fail "cron accepted unsupported interval $bad_interval"
		fi
	done
	special_bin="$work/grok pat'percent%ol"
	special_dir="$work/watch state'percent%"
	cp "$fake" "$special_bin"
	sh "$script" install --bin "$special_bin" --dir "$special_dir" >"$work/quoted-plan"
	grep -F "watch state'\\''percent\\%/watch-apps.sh" "$work/quoted-plan" >/dev/null || fail "cron script path was not shell-quoted"
	grep -F "grok pat'\\''percent\\%ol" "$work/quoted-plan" >/dev/null || fail "cron binary path was not shell-quoted"
fi
HOME="$work/home" sh "$script" uninstall --dir "$work/inst" >/dev/null
[ ! -e "$work/inst" ] || fail "uninstall wrote without --apply"

# Bad input is refused before anything runs.
for bad in "--keyword ab" "--keyword a;b" "--domain x" "--interval 2" "--interval 1e3" "--bogus"; do
	# shellcheck disable=SC2086
	if sh "$script" run --bin "$fake" --dir "$dir" $bad >/dev/null 2>&1; then
		fail "accepted $bad"
	fi
done

sh "$script" status --dir "$dir" | grep -q 'apps watched: 1' || fail "status does not count apps"
echo "OK: watch-apps.sh"
