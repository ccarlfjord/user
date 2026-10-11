# user

OpenID Connect provider for ccarlfjord: it owns accounts, authentication, and
sessions, and is the identity source other services and relying parties are
meant to sign in through. The account, session, and token machinery is the
substrate. Discovery and the public key set are live
(`/.well-known/openid-configuration`, `/.well-known/jwks.json`) and tokens are
signed with ES256 (P-256); the rest of the OIDC surface (`/authorize`,
`/token`, `/userinfo`) is not built yet — see the OIDC section in `TODO.md`.

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

Migrations in `migrations/` are applied by hand, one file at a time, for now
(see `TODO.md`); there is no runner yet.
