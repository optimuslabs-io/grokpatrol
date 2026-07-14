#!/usr/bin/env bash
# Builds a synthetic COMPROMISED host: every host-side IoC from the incident,
# planted deliberately. This is grokpatrol's end-to-end proof -- there is no real
# Grok install to test against, so the compromised case has to be constructed.
#
# Nothing here is committed to the repo. Files carrying a live IoC string trip
# corporate EDR, so the fixture is generated on demand and thrown away.
set -euo pipefail

HOME_DIR="${1:?usage: make_fakehome.sh <dir>}"
rm -rf "$HOME_DIR"
mkdir -p "$HOME_DIR"

BUCKET="grok-code-session-traces"
GROK="$HOME_DIR/.grok"
mkdir -p "$GROK/logs" "$GROK/upload_queue/sess-a1/turn-3" "$HOME_DIR/.local/bin"

# --- 1. Logs, with the start/enqueue pair SPLIT ACROSS A ROTATION BOUNDARY ------
# This is the case a per-file correlator gets wrong: it would report payments-api
# as COLLECTED-ONLY when an archive was in fact queued.
cat > "$GROK/logs/unified.jsonl.1" <<EOF
{"event":"repo_state.upload.start","sid":"sess-a1","ctx":{"turn_number":3,"repo_path":"$HOME_DIR/work/payments-api"},"ts":"2026-06-30T10:00:00Z","version":"0.2.93"}
{"event":"repo_state.upload.start","sid":"sess-a1","ctx":{"turn_number":3,"repo_path":"$HOME_DIR/work/payments-api"},"ts":"2026-06-30T10:00:01Z"}
EOF

cat > "$GROK/logs/unified.jsonl" <<EOF
{"event":"repo_state.upload.enqueued","sid":"sess-a1","ctx":{"turn_number":3},"gcs_path":"gs://$BUCKET/sess-a1/3/before_codebase.tar.gz","ts":"2026-06-30T10:00:05Z"}
{"event":"repo_state.upload.enqueued","sid":"sess-a1","ctx":{"turn_number":3},"gcs_path":"gs://$BUCKET/sess-a1/3/after_codebase.tar.gz","ts":"2026-06-30T10:02:00Z"}
{"event":"repo_state.upload.start","sid":"sess-b2","ctx":{"turn_number":1,"repo_path":"$HOME_DIR/work/scratch"},"ts":"2026-06-12T09:00:00Z"}
{"event":"agent.turn.complete","sid":"sess-b2","ctx":{"turn_number":1}}
EOF

# A gzipped older rotation, to prove those are read too.
printf '%s\n' \
  "{\"event\":\"repo_state.upload.start\",\"sid\":\"sess-c3\",\"ctx\":{\"turn_number\":1,\"repo_path\":\"$HOME_DIR/work/infra\"},\"ts\":\"2026-05-01T00:00:00Z\"}" \
  "{\"event\":\"repo_state.upload.enqueued\",\"sid\":\"sess-c3\",\"ctx\":{\"turn_number\":1},\"gcs_path\":\"gs://$BUCKET/sess-c3/1/after_codebase.tar.gz\",\"ts\":\"2026-05-01T00:01:00Z\"}" \
  | gzip > "$GROK/logs/unified.jsonl.2.gz"

# --- 2. config.toml WITHOUT the mitigation ------------------------------------
cat > "$GROK/config.toml" <<'EOF'
[harness]
model = "grok-code-fast"
telemetry = true
EOF

# --- 3. auth.json: exists, and grokpatrol must never open it -------------------
echo '{"key":"xai-SECRET-TOKEN-THAT-MUST-NEVER-BE-PRINTED"}' > "$GROK/auth.json"

# --- 4. A populated upload_queue with a bucket-referencing manifest ------------
cat > "$GROK/upload_queue/sess-a1/turn-3/metadata.json" <<EOF
{
  "session_id": "sess-a1",
  "files": [
    {"local": "$HOME_DIR/work/payments-api/.env.production", "gcs": "gs://$BUCKET/sess-a1/3/before_codebase.tar.gz"},
    {"local": "$HOME_DIR/work/payments-api/src/main.go",     "gcs": "gs://$BUCKET/sess-a1/3/before_codebase.tar.gz"}
  ]
}
EOF
head -c 200000 /dev/urandom | gzip > "$GROK/upload_queue/sess-a1/turn-3/before_codebase.tar.gz"
head -c 180000 /dev/urandom | gzip > "$GROK/upload_queue/sess-a1/turn-3/after_codebase.tar.gz"

# --- 5. A fake grok binary carrying the bucket name, planted at a CHUNK BOUNDARY.
# 256 KiB is the matcher's chunk size; putting the marker so it straddles that
# boundary exercises the overlap carry against a real file on disk, not just a
# unit test buffer.
BIN="$HOME_DIR/.local/bin/grok"
python3 - "$BIN" "$BUCKET" <<'PY'
import sys
path, bucket = sys.argv[1], sys.argv[2]
CHUNK = 256 * 1024
marker = bucket.encode()
at = CHUNK - len(marker) // 2          # straddles the boundary
blob = bytearray(b"\x7fELF" + b"\x02\x01\x01\x00" + b"A" * (CHUNK * 2))
blob[at:at + len(marker)] = marker
extra = b'{"name":"grok","version":"0.2.93"}'
blob[1000:1000 + len(extra)] = extra
open(path, "wb").write(bytes(blob))
PY
chmod +x "$BIN"
echo '0.2.93' > "$GROK/version"

# --- 6. The repo that was taken: secrets COMMITTED, then DELETED ---------------
# They are gone from the working tree but still reachable from HEAD, so they were
# in the uploaded object set -- and the owner cannot see them in their checkout.
REPO="$HOME_DIR/work/payments-api"
mkdir -p "$REPO/certs" "$REPO/src"
cd "$REPO"
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.invalid
export GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.invalid
export GIT_AUTHOR_DATE=2026-06-01T00:00:00Z GIT_COMMITTER_DATE=2026-06-01T00:00:00Z
git init -q --initial-branch=main
echo 'package main' > src/main.go
echo 'DATABASE_URL=postgres://user:hunter2@prod/db' > .env.production
echo '-----BEGIN PRIVATE KEY-----' > certs/prod.pem
echo 'DATABASE_URL=' > .env.example
git add -A >/dev/null && git commit -qm 'initial'
git rm -q .env.production certs/prod.pem
git commit -qm 'remove secrets (they live on in git history)'
echo 'api_token = "abc"' > terraform.tfvars
git add -A >/dev/null && git commit -qm 'add tfvars'

# A second repo, collected but never enqueued -> COLLECTED-ONLY.
mkdir -p "$HOME_DIR/work/scratch" && cd "$HOME_DIR/work/scratch"
git init -q --initial-branch=main
echo 'notes' > README.md
git add -A >/dev/null && git commit -qm 'init'

echo "fake compromised home built at: $HOME_DIR"
