# blankres design

How blankres works, and how to run and test it. The short version of why it exists is in
[README.md](README.md).

## How it avoids apport's cost

| Apport | blankres |
| --- | --- |
| Registers as the kernel's `core_pattern` handler, so a dying process is pinned while a **Python interpreter cold-starts** and drains the core through a pipe. | Consumes `systemd-coredump`'s journal entries. By the time we look, the core is written and the process is reaped — **nothing is on the crash path**. |
| Re-encodes the whole core as base64+zlib into the `.crash` file. | References the core in place. It is already zstd on disk; the upload streams those frames. |
| `dpkg --verify` md5sums **every file** in the package. | Hashes only the executable and the libraries actually mapped at crash time — tens of files, not thousands. |
| Forks `dpkg-query` per lookup. | One in-memory path index built from `/var/lib/dpkg/info/*.list` at startup. |
| Collects everything eagerly, for crashes nobody ever sends. | **Two stages.** Most crashes stop at a ~1 KB event. |

## Two-stage reporting

```
crash → systemd-coredump → journal entry
      → blankresd: signature + stage-1 event  → POST /v1/events
                                               ↓
                          need_payload: false → delete core, done   (the common case)
                          need_payload: true  → write /var/crash/<uid>/<name>.report
                                               → GTK window: review + consent
                                               → stage-2 upload (metadata + streamed core)
```

**Stage 1** is automatic, gated on a one-time opt-in, and carries no memory contents, no command
line and no environment — just enough to count the crash and identify the bug.

**Stage 2** is the core dump. It is collected only when the server asks for one, and uploaded only
after explicit, per-report consent. The server asks only while it has fewer than *N* stored cores
for that signature, which is what turns a fleet-wide flood of gigabyte cores into a handful.

The load-bearing part is the **signature**: a dedup key computed without opening the core, from the
stack trace `systemd-coredump` embeds in its journal message. Frames are normalized to
module-relative offsets, because absolute addresses shift per boot under ASLR and hashing them
would silently defeat deduplication while still looking like it works.

## Crates

| Crate | What it is |
| --- | --- |
| `blankres-report` | Report model, the signature algorithm, redaction, an apport `.crash` reader |
| `blankres-collect` | Collectors, split along the stage boundary; the dpkg backend |
| `blankres-client` | HTTP client for the protocol |
| `blankres-session` | The on-disk contract for pending reports, and the consent logic |
| `blankres-daemon` | `blankresd` — journal watcher and decision loop |
| `blankres-gtk` | `blankres-gtk` — the GTK4/libadwaita consent window |
| `blankres-cli` | `blankres` — the same decisions, headless |
| `blankres-hooks` | `blankres-apt-hook` — failed package installs and upgrades |
| `blankres-server` | `blankres-ingest` — axum + Postgres ingest |

## Running it

The daemon needs `systemd-coredump` with cores saved to disk:

```bash
sudo apt install systemd-coredump
printf '[Coredump]\nStorage=external\n' | sudo tee /etc/systemd/coredump.conf.d/blankres.conf
```

The server needs a Postgres; it applies its own migrations at startup, so an empty database is
enough:

```bash
export DATABASE_URL=postgres://blankres:blankres@127.0.0.1:5432/blankres
export BLANKRES_TOKEN=dev-fleet-token
export BLANKRES_STORAGE_ROOT=/var/lib/blankres-ingest
cargo run -p blankres-server --bin blankres-ingest
```

Then point the client at it in `/etc/blankres/client.json` and set `telemetry_enabled` to `true`.

```bash
blankres list             # crashes awaiting a decision
blankres show firefox     # everything that would be transmitted
blankres send firefox     # upload it
blankres ignore firefox   # never ask about this problem again
```

## Running the server with Docker

The ingest server and its database, locally:

```bash
make up          # docker compose up -d --build
curl -s localhost:8080/healthz
make logs        # follow the server
make down        # stop; add KEEP=0 to delete the stored crash data too
```

`make build-docker` builds just the image (`blankres-ingest:0.2.1`). It is the server only: the
client reads the host's journal, dpkg database and saved core dumps, so it runs on the machine
being reported on and ships as a `.deb` instead.

The compose file is a development deployment. The token is a placeholder and the server speaks
plain HTTP, which belongs behind a reverse proxy terminating TLS. Override anything through the
environment:

```bash
BLANKRES_TOKEN=... BLANKRES_PORT=9000 BLANKRES_PAYLOADS_PER_SIGNATURE=1 make up
```

Point a client at it by setting `BLANKRES_SERVER_URL=http://localhost:8080` and `BLANKRES_TOKEN`,
or by editing `/etc/blankres/client.json`.

## Testing

```bash
cargo test                                   # everything that needs no database
BLANKRES_TEST_DATABASE_URL=postgres://... cargo test   # adds the end-to-end suites
```

The database-backed suites skip rather than fail when that variable is unset. A throwaway Postgres:

```bash
docker run --rm -d --name blankres-pg -e POSTGRES_PASSWORD=blankres \
  -e POSTGRES_USER=blankres -e POSTGRES_DB=blankres -p 5432:5432 postgres:16-alpine
```

## Privacy

- The stage-1 opt-in is a real gate: with it off the daemon reads nothing and sends nothing.
- A core dump is a copy of process memory and always needs per-report consent. The window states
  its size in plain language and lists every field that would be transmitted.
- The environment is filtered by allowlist, not blocklist, and the report says how many variables
  were withheld rather than presenting a partial environment as complete.
- Pending reports live in per-user directories, mode `0700`, so one user's crash cannot be read by
  another.
- The machine identifier and its threat model are documented in
  [docs/machine-identifier.md](docs/machine-identifier.md).

## Building the Debian package

```bash
dpkg-buildpackage -us -uc -b
```

Produces a single `blankres` package containing the daemon, both front ends and the apt hook. If
your toolchain comes from rustup rather than the `cargo`/`rustc` packages, add `-d` to skip the
build-dependency check.
