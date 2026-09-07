#!/usr/bin/env bash
# Launch the consent dialog against a throwaway crash report.
#
# The dialog only ever shows payloads the server has asked for, so there is nothing to look at
# until one exists. This builds one in a temporary directory and points the UI at it; nothing
# under /var or /etc is touched.
#
# Usage:
#   scripts/demo-dialog.sh                       # dialog only; Send will fail, there is no server
#   scripts/demo-dialog.sh --with-server         # also start Postgres and the ingest server, so
#                                                # Send actually completes end to end
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT=$(mktemp -d /tmp/blankres-demo.XXXXXX)
UID_N=$(id -u)
CORE_MB=${CORE_MB:-64}
WITH_SERVER=0
[[ "${1:-}" == "--with-server" ]] && WITH_SERVER=1

cleanup() {
  [[ -n "${SERVER_PID:-}" ]] && kill "$SERVER_PID" 2>/dev/null || true
  [[ $WITH_SERVER == 1 ]] && docker rm -f blankres-demo-pg >/dev/null 2>&1 || true
  rm -rf "$ROOT"
}
trap cleanup EXIT

echo "Building..."
cargo build --release -p blankres-gtk >/dev/null

mkdir -p "$ROOT/crash/$UID_N" "$ROOT/state"
# A stand-in for the core dump. Its size is what the dialog quotes back to the user, so make it
# large enough that the number means something.
head -c $((CORE_MB * 1024 * 1024)) /dev/urandom > "$ROOT/core.zst"

SERVER_URL="http://127.0.0.1:18080"
TOKEN="dev-fleet-token"

if [[ $WITH_SERVER == 1 ]]; then
  echo "Starting Postgres..."
  docker run -d --rm --name blankres-demo-pg \
    -e POSTGRES_PASSWORD=blankres -e POSTGRES_USER=blankres -e POSTGRES_DB=blankres \
    -p 55432:5432 postgres:16-alpine >/dev/null
  for _ in $(seq 1 30); do
    docker exec blankres-demo-pg pg_isready -U blankres -q 2>/dev/null && break
    sleep 1
  done

  echo "Starting the ingest server..."
  cargo build --release -p blankres-server >/dev/null
  DATABASE_URL="postgres://blankres:blankres@127.0.0.1:55432/blankres" \
  BLANKRES_TOKEN="$TOKEN" \
  BLANKRES_STORAGE_ROOT="$ROOT/store" \
  BLANKRES_BIND="127.0.0.1:18080" \
    ./target/release/blankres-ingest > "$ROOT/server.log" 2>&1 &
  SERVER_PID=$!
  for _ in $(seq 1 30); do
    curl -sf "$SERVER_URL/healthz" >/dev/null && break
    sleep 1
  done
fi

cat > "$ROOT/client.json" <<EOF
{"endpoint":{"url":"$SERVER_URL","token":"$TOKEN","timeout_secs":30},
 "telemetry_enabled":true,"state_dir":"$ROOT/state","crash_dir":"$ROOT/crash",
 "kernel_oops":false,"delete_declined_cores":true}
EOF

# Build the pending report. With a server running, the upload token is a real one obtained from
# it, so Send completes for real; without one it is a placeholder and Send reports a connection
# error, which is itself worth seeing.
WITH_SERVER=$WITH_SERVER ROOT=$ROOT UID_N=$UID_N SERVER_URL=$SERVER_URL TOKEN=$TOKEN \
python3 - <<'PY'
import json, os, time, urllib.request

root, uid = os.environ["ROOT"], int(os.environ["UID_N"])
core = f"{root}/core.zst"
size = os.path.getsize(core)

event = {
    "schema": 1,
    "signature": {"hash": "d4e9" * 16, "precision": "precise",
                  "frames": ["js::GCRuntime::collect", "nsThread::ProcessNextEvent", "main"]},
    "kind": "native_crash", "timestamp": int(time.time()),
    "executable": "/usr/lib/firefox/firefox", "signal": 11, "signal_name": "SIGSEGV",
    "package": {"name": "firefox", "version": "128.0+build1-0ubuntu1", "source": "firefox"},
    "system": {"distro": "Debian GNU/Linux", "distro_version": "14",
               "architecture": "x86_64", "kernel_version": "7.1.12+deb14-amd64"},
    "machine_id": "e" * 64, "crash_count": 2, "client_version": "0.1.0",
    "core_available": True, "core_size": size,
}

directive = {"id": "demo-event", "need_payload": True, "upload_token": "f" * 64,
             "max_bytes": size + 1048576, "expires_at": int(time.time()) + 3600}

if os.environ["WITH_SERVER"] == "1":
    req = urllib.request.Request(
        f"{os.environ['SERVER_URL']}/v1/events",
        data=json.dumps({"events": [event]}).encode(),
        headers={"Authorization": f"Bearer {os.environ['TOKEN']}",
                 "Content-Type": "application/json"})
    directive = json.load(urllib.request.urlopen(req))["directives"][0]

pending = {
    "report": {
        "event": event, "directive_id": directive["id"],
        "command_line": ["/usr/lib/firefox/firefox", "--new-window"],
        "environment": {"LANG": "en_US.UTF-8", "PATH": "/usr/bin:/bin",
                        "XDG_SESSION_TYPE": "wayland"},
        "environment_withheld": 37, "uid": uid,
        "stack_trace": [
            {"function": "js::GCRuntime::collect", "module": "libxul.so", "module_offset": 123456},
            {"function": "nsThread::ProcessNextEvent", "module": "libxul.so", "module_offset": 223456},
            {"function": "main", "module": "firefox", "module_offset": 4660}],
        "modified_files": [],
        "attachments": [
            {"storage": "file", "name": "core-dump", "path": core,
             "size": size, "compression": "zstd"},
            {"storage": "inline", "name": "proc-maps",
             "content": "55f6a1b2b000-55f6a1b2c000 r-xp /usr/lib/firefox/firefox\n"
                        "7f8a1b200000-7f8a1b228000 r-xp /usr/lib/firefox/libxul.so\n"}],
        "skipped": [{"name": "apt-term-log", "reason": "read budget of 67108864 bytes exhausted"}],
    },
    "directive": directive,
    "written_at": int(time.time()),
}

path = f"{root}/crash/{uid}/usr_lib_firefox_firefox.{uid}.report"
open(path, "w").write(json.dumps(pending, indent=1))
os.chmod(path, 0o640)
PY

echo
echo "Crash directory: $ROOT/crash/$UID_N"
if [[ $WITH_SERVER == 1 ]]; then
  echo "Send will upload for real; the blob lands in $ROOT/store/blobs/"
else
  echo "No server: Send will show a connection error. Use --with-server for a real upload."
fi
echo "Close the window to clean up."
echo

BLANKRES_CONFIG="$ROOT/client.json" ./target/release/blankres-gtk
