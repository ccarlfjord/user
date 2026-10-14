# user

OpenID Connect provider for ccarlfjord: it owns accounts, authentication, and
sessions, and is the identity source other services and relying parties are
meant to sign in through. The account, session, and token machinery is the
substrate. Discovery and the public key set are live
(`/.well-known/openid-configuration`, `/.well-known/jwks.json`) and tokens are
signed with ES256 (P-256). The authorization endpoint (`/authorize`) is live:
request validation, an interactive login step, consent, and code issuance —
and relying parties register themselves via RFC 7591 dynamic registration
(`POST /register`, gated by a single-use registration token). See the OIDC
section in `TODO.md`. `/token` and `/userinfo` are not built yet.

## Development

Dev containers are run with **Podman** (not Docker). Postgres is the example
used here: the service and its tests default to
`postgresql://postgres:postgres@localhost:5432`, so a `postgres-dev` container
publishing `5432` on the host is all that is needed. The default password is
`postgres`.

    podman run -d --name postgres-dev \
        -e POSTGRES_PASSWORD=postgres \
        -p 5432:5432 \
        -v postgres-dev-data:/var/lib/postgresql \
        postgres

Connect with `podman exec -it postgres-dev psql -U postgres`, or any host
client via `localhost:5432` — the port forward reaches the container, there is
no host Postgres.

Migrations in `migrations/` are applied with the
[golang-migrate](https://github.com/golang-migrate/migrate) CLI, the standard
way this project runs migrations. There is no startup migration runner and no
`goose`.

Install the CLI with the Postgres driver compiled in, since the build tag is
required or it will not recognize the `postgres://` scheme:

    go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest

The driver needs the `postgres://` scheme (not `postgresql://`) and
`sslmode=disable` for the local server:

    export DATABASE_URL='postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable'

    migrate -path migrations -database "$DATABASE_URL" up        # apply pending
    migrate -path migrations -database "$DATABASE_URL" down 1    # revert the last
    migrate -path migrations -database "$DATABASE_URL" version   # current version + dirty state

`migrate create -ext sql -dir migrations -seq <name>` scaffolds a new pair;
files are named `{version}_{name}.up.sql` / `.down.sql`.

The schema predates the runner, so an existing database has no
`schema_migrations` table. Baseline it once before the first `up`, or migrate
replays every migration from zero:

    migrate -path migrations -database "$DATABASE_URL" force 10  # record 10 as applied, run nothing
    migrate -path migrations -database "$DATABASE_URL" up

`migtest` is a scratch database for exercising the full chain (`up` then
`down`) before applying anything to `postgres`.
