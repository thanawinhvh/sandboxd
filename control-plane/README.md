# sandboxd — control plane

The Go control plane for [sandboxd](../README.md). A single binary that drives
the Docker daemon (via the `docker` CLI), stores state in SQLite, runs the idle
and pressure reapers, and serves the HTTP API and the wake path.

See [`../ARCHITECTURE.md`](../ARCHITECTURE.md) for the full design.

## Build & test

```bash
go build ./...
go test ./...
go vet ./...
```

`sandboxd` uses cgo (mattn/go-sqlite3); the container build (`Dockerfile`) sets
`CGO_ENABLED=1`. `runtimed` (`cmd/runtimed`) is CGO-free and is compiled into
the sandbox base image instead.

## Packages

| Package | Responsibility |
|---|---|
| `cmd/sandboxd` | daemon entrypoint, env wiring, background goroutines |
| `cmd/runtimed` | in-sandbox supervisor (baked into the base image) |
| `internal/docker` | thin typed wrapper over the `docker` CLI |
| `internal/loopback` | per-sandbox workspace storage (directory-backed) |
| `internal/traefik` | preview-route label generation |
| `internal/reaper` | idle (stop-on-idle) + host-memory pressure reapers |
| `internal/wake` | wake-on-request handler + warming page |
| `internal/reconcile` | boot-time convergence of Docker → SQLite |
| `internal/store` | SQLite access + numbered migrations |
| `internal/api` | HTTP handlers (`/sandbox*`, `/v1/*`, wake, forward-auth) |
| `internal/auth` | service-token + preview-token auth (optional) |
| `internal/terminal` | WebSocket terminal: stdlib-only RFC 6455 + PTY session (`docker exec -it`) |

## Configuration

All runtime configuration is via environment variables, set by the compose file
from `../.env`. The ones the OSS build adds or changes:

| Variable | Default | Purpose |
|---|---|---|
| `PREVIEW_DOMAIN` | `localhost` | domain preview URLs hang off |
| `PREVIEW_ENTRYPOINT` | `web` | Traefik entrypoint on preview routers |
| `PREVIEW_TLS` | `false` | emit `tls=true` on preview routers |
| `SANDBOXD_NETWORK` | `sandboxd_net` | docker network sandboxes join |
| `SANDBOXD_USERNS` | `host` | `--userns` for sandboxes + the seed container |
| `SANDBOXD_DATA_DIR` | `/var/lib/sandboxed` | workspaces + SQLite + logs |
| `SANDBOXD_SET_MEMORY_HIGH` | `false` | write cgroup `memory.high` (needs host cgroup access) |
| `SANDBOXD_IMAGE` | `sandboxd-base:1.0.0` | per-sandbox base image |
| `SANDBOXD_API_AUTH_DISABLED` | `true` | open API for local use |
| `SANDBOXD_API_TOKENS` | — | `name=secret` pairs for service-token auth |
| `SANDBOXD_IDLE_THRESHOLD_SECONDS` | `2100` | idle window before `docker stop` |

## API sketch

```
POST   /sandbox                      create (body: {"ports":[...]}; id optional)
GET    /sandboxes                    list
GET    /sandbox/{id}                 get
POST   /sandbox/{id}/exec            run a command (non-interactive)
DELETE /sandbox/{id}                 destroy container (workspace kept)
POST   /sandbox/{id}/purge           destroy + delete workspace
POST   /v1/sandboxes/{id}/stop       stop (idle); wakes on next preview hit
POST   /v1/sandboxes/{id}/tasks      submit a coding task to runtimed
PUT    /v1/sandboxes/{id}/files      write files into the workspace
GET    /v1/sandboxes/{id}/terminal   WebSocket terminal (see below)
GET    /healthz  GET /readyz         liveness / readiness
```

## Terminal (WebSocket)

`GET /v1/sandboxes/{id}/terminal?cols=80&rows=24` upgrades to a
WebSocket carrying one interactive `bash` inside the sandbox
(`docker exec -it` on a real PTY — colors, vim/htop, job control all
work). A stopped sandbox is woken first; an open terminal counts as
live activity, so the idle reaper never stops a sandbox mid-session.

Auth accepts two credentials on `?token=` (this path only —
browsers can't set headers on `new WebSocket()`):

- local dev: a service token from `SANDBOXD_API_TOKENS`;
- production: a short-lived upstream-signed terminal JWT
  (`aud: "sandbox-terminal"`, `sandbox_id` = this sandbox, 5–15 min
  expiry), verified against `SANDBOXD_PREVIEW_TOKEN_SECRETS`. Mint one
  per session server-side; a leaked URL then expires in minutes
  instead of exposing a long-lived secret.

(`Authorization: Bearer <service-token>` also works, for backends that
proxy the WebSocket.)

Terminal JWT shape (compact JWS, `kid` header = secret id):

```
header  {"alg":"HS256","typ":"JWT","kid":"v1"}
claims  {"iss":"…","iat":…,"exp":…,"aud":"sandbox-terminal",
         "sub":"<upstream-user-id>","sandbox_id":"<sandbox-id>"}
```

Wire protocol (see `internal/terminal` for the contract):

```
client → server:  binary  stdin bytes (as-is)
                  text    {"type":"resize","cols":N,"rows":M}
server → client:  binary  shell output bytes (as-is)
                  text    {"type":"exit","code":N}  (once, then close)
                          {"type":"error","message":"..."} (fatal, then close)
```

Minimal xterm.js wiring:

```js
const ws = new WebSocket(`ws://127.0.0.1:9090/v1/sandboxes/${id}/terminal?token=${TOKEN}`);
ws.binaryType = "arraybuffer";
const term = new Terminal();
term.onData(d => ws.send(new TextEncoder().encode(d))); // stdin
ws.onmessage = ev => {
  if (typeof ev.data === "string") {
    const msg = JSON.parse(ev.data);                    // exit / error
    if (msg.type === "exit") term.write(`\r\nexit ${msg.code}\r\n`);
  } else term.write(new Uint8Array(ev.data));           // shell output
};
term.onResize(({cols, rows}) =>
  ws.send(JSON.stringify({type: "resize", cols, rows})));
```
