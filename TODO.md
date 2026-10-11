# TODO

State as of the current working tree (builds clean, `go vet` clean, `go test ./...` green against a local Postgres).
Ordered by priority; every item is grounded in the code as it stands.

## Landed

- [x] `argon2` extraction finished: `rest/user.go` derives through the package-level
      `argon2.GenerateSalt/HashPassword/Validate`, `main_test.go` uses `argon2.NewDefaultArgon2id()`.
- [x] The relocation (generated `signing_key`/`verification_token` queries, `sql/`, `static/`, session
      validation) is committed in `2342a24`; the working tree is clean apart from this file.
- [x] `sqlc generate` reproduces the checked-in tree unchanged (`sqlc v1.31.1`).
- [x] `000004_session_invalidation` is applied to the local database by hand, as every migration is until a
      runner exists (see the P1 item); the `down` really reverses the `up`, unlike `000002`/`000003`.

## P0 — OIDC provider

This service exists to be an OpenID Connect provider. The account, session, and
token machinery above is the substrate; everything below is what still stands
between it and a relying party being able to discover it, authenticate a user,
and validate the result.

- [x] Discovery: `GET /.well-known/openid-configuration` (`rest/oidc.go`) serves the document a relying
      party fetches first: `issuer`, `jwks_uri`, `id_token_signing_alg_values_supported` (`["ES256"]`),
      `subject_types_supported` (`["public"]`), `scopes_supported`, and `claims_supported`. The
      authorization/token/userinfo endpoints are deliberately absent until they exist rather than advertised
      as 404s. The issuer is resolved once at start-up by `oidcIssuer` from `OIDC_ISSUER`, falling back to
      `PUBLIC_BASE_URL`, so every future `iss` can match one configured URL.
- [x] JWKS and asymmetric signing: the service signs with a persisted ES256 (P-256) key. `loadSigningKey`
      (`main.go`) reads the `oidc_signing_key` row, generates a key only on first boot with a race-safe
      `CreateSigningKey` (`ON CONFLICT DO NOTHING`) plus read-back, and refuses a stored key that is not
      P-256. `GET /.well-known/jwks.json` publishes its public half as an EC JWK (`kty`, `crv`, `x`, `y`,
      `use: sig`, `alg: ES256`) whose `kid` is the RFC 7638 thumbprint (`keyID`, `rest/oidc.go`), so an RP can
      verify without holding anything that mints. Sessions moved off HS256 with it: `mintSession` signs ES256
      and `requireSession`/`sessionKey` verify against the public key, pinned to that one algorithm.
- [x] `kid` on tokens: `mintSession` sets the JWT header's `kid` to the RFC 7638 thumbprint of the signing
      key, and `sessionKey` refuses a token whose `kid` is missing or is not the current key. With one key
      that equality check is all there is; it becomes a lookup over the published set when rotation lands.
- [ ] Multi-key rotation: one key exists and the JWKS advertises one `kid`. Rotation is overlap-only: generate
      a new key and sign with it, publish both public keys in the JWKS, and drop the old one only once the
      longest signed-token lifetime has passed since it was last used to sign. Nothing is revoked or deleted:
      a token whose `kid` is no longer advertised has already expired. The bound is `sessionTTL` (1h, plus a
      clock-skew margin), because refresh tokens are opaque random values and are not signed. Needs multiple
      key rows selected by `created_at` (the fixed `oidc_signing_key` name holds only one), a JWKS that hides
      a key after that window, and a `sessionKey` that verifies against the old key during the overlap.
      Keeping a retired key published indefinitely is harmless at this scale, so the time filter is tidy-up,
      not correctness (see the P1 signing-key item too).
- [ ] Clients: no registry of relying parties — no `client_id`, no
      `client_secret`, no redirect URI allowlist, no scopes anywhere in the
      schema. `/authorize` cannot know where a user may be sent back to until
      clients are approved (or dynamically registered).
- [ ] Authorization endpoint: no `/authorize`. It needs `response_type=code`,
      `client_id`, exact `redirect_uri` validation against the client, `scope`,
      `state`, `nonce`, and a browser login/consent step. Login today is the
      JSON `POST /v1/login` (`rest/user.go`) and the only HTML login form is the
      admin panel's (`/admin/login`, `rest/admin.go`), so the interactive flow
      does not exist.
- [ ] Authorization codes and PKCE: no code table and no `code_challenge`/
      `code_verifier`. Codes must be single-use, short-lived, bound to the
      client, redirect URI, and nonce, and consumed atomically — the pattern
      `ConsumeRefreshToken`/`ConsumePasswordResetToken` already follow.
- [ ] Token endpoint: no `/token`. It has to exchange an authorization code
      (and a refresh token) for an ID token and an access token, with client
      authentication. `refresh` (`rest/user.go`) already does single-use,
      rotating, epoch-checked refresh, but against this API's own
      `SessionResponse`, not an OIDC client.
- [ ] ID token: absent. `mintSession` (`rest/user.go`) produces an
      access-token-shaped JWT with a fixed `aud` (`sessionAudience`) and no
      `nonce`, `auth_time`, `email`, or `email_verified`. An ID token's `aud` is
      the client id and the code flow requires `nonce`.
- [ ] UserInfo: no `/userinfo` endpoint reading the access token and returning
      `sub` plus the granted claims (at least `email`, `email_verified`).
- [ ] `email_verified`: `users` has `active` (`000001`), not an email
      verification flag, so the `email` claim has nothing truthful to say about
      whether the address was confirmed — even though signup already issues a
      verification token (`verification_tokens`, `000003`).
- [ ] Session/access-token split: the same ES256 JWT gates this service's own
      API (`requireSession`, `rest/server.go`) and would be what is handed to a
      relying party. OIDC wants a short-lived access token whose audience is the
      resource server and an ID token for the client, distinct from the internal
      admin session cookie the panel uses. The key is now shared too — internal
      sessions and future ID tokens are signed with the same one.
- [ ] Logout and revocation: no `end_session_endpoint`, and no `/introspect`
      or `/revoke`. Without a `jti` (below) there is no per-session revocation,
      and there is no RP-initiated logout at all.

## P0 — handlers

- [x] `deleteUser` (`rest/user.go`) implemented on `DELETE /v1/user`: body is `{"id","email"}`, ID takes
      precedence, success is `204`. `DeleteUser` in `sql/user.sql` became `:execrows` so an authorized request
      naming a row that does not exist answers `404` instead of a false `204`; verification tokens go with the
      row via `ON DELETE CASCADE`. Authorization runs through `authorizeTarget`/`resolveTarget`: admins may name
      anyone, everyone else is held to their own id or address *before* any lookup, so the refusal (`403`, empty
      body) never reports whether the target exists — a non-admin's request for another address does not reach
      the store at all. `userStore` (`rest/server.go`) and `fakeStore` (`rest/user_test.go`) gained
      `DeleteUser`/`UpdateUser`.
- [x] `updateUser` (`rest/user.go`) implemented as a partial update on `PATCH /v1/user`, target always named by
      `id` — an `email` in the body means "change the address", never "pick the account". Field set: `email`,
      `password`, `active`, `admin`; a field absent from the body (or JSON `null`) keeps its stored value. A
      non-admin may write only their own `email` and `password`; `active`/`admin` are refused with `403` before
      the row is read, even on their own account, as is any target but themselves. A new password gets a fresh
      salt, a taken address is `409`, a missing target `404`, success is `200` with the public user. Untouched
      fields are carried over because `UpdateUser` rewrites the whole row — which also means two concurrent
      updates to one account can drop one of them (no optimistic locking anywhere in the service yet).
- [x] `getUser`'s fate settled: the unrouted email-body lookup is gone, and `GET /v1/user` now serves the same
      handler under `requireSession` — with no query it returns the caller's own record straight from the
      request context (no lookup, so a client no longer has to decode the JWT `sub` to learn its own id), and
      with `?email=` it returns the named account through the same `authorizeTarget`/`resolveTarget` gate as
      DELETE/PATCH. An admin may name anyone, a non-admin only their own address, refused before any lookup —
      so the route that used to be an enumeration oracle now distinguishes `403` (not yours) from `404` (no such
      account) only for admins, who can probe anyway. `GET /v1/user/{id}` remains for id-based reads.
- [x] `GET /v1/user/{id}` required no session and `publicUser` returns `email` → unauthenticated PII lookup.
      Resolved by requiring a session (see the item above) plus a self-or-admin check: `mayAccessUser`
      (`rest/server.go`) allows the caller's own id and admins, everything else gets `403` — decided before the
      lookup, so a denial does not confirm the target exists. `email` is still in the response, but only for
      self or admin callers.

## P0 — authentication

- [x] Session validation: `requireSession` (`rest/server.go`) parses the `Authorization: Bearer` token with
      `jwt.ParseWithClaims`, pins the signing method to HS256 (`jwt.WithValidMethods` plus an HMAC-only key
      func), requires a UUID `sub` and an `exp` claim, then resolves the subject through `GetUserById` and
      rejects the request when the account is gone or `active = false`. It gates `GET /v1/user/{id}` and
      `DELETE`/`PATCH /v1/user`; signup, login and verify stay public. The resolved caller is attached to the
      request context (`callerFrom`). Tests in `rest/user_test.go`.
      Remaining gaps: no `jti`, issuer/audience, logout or revocation list; `requireSession` adds one
      `GetUserById` per protected request.
- [x] Account enumeration by timing on `createUser`: the derivation now runs *before* the email lookup, so a
      signup attempt for a registered address pays the same argon2id cost as a free one — measured 47.9ms
      (registered) vs 46.8ms (free), delta 1.1ms, against 1.0ms vs 42.7ms (42.5x) before. No decoy needed here:
      the hash does not depend on the row, so ordering removes the branch instead of papering over it. Cost is
      one derivation per attempt either way, which is what the free path already paid.
- [ ] No rate limiting on `POST /v1/login` or `POST /v1/user`; argon2 cost makes both cheap DoS and cheap
      password brute-force targets.
- [ ] `GET /v1/verify?token=...` puts the token in the URL, so it leaks through referrers, proxy and browser
      history. Move redemption behind a POST/confirm page (single-use is already enforced by deleting tokens).
- [ ] Only a minimum password length is enforced (`len(req.Password) < 8`); no maximum, so argon2 runs on
      unbounded input. Add an upper bound.
- [x] Email normalization: `normalizeEmail` (`rest/user.go`) trims surrounding whitespace and lowercases, and
      every entry point that accepts, stores, or compares an address applies it — signup, login (inside
      `authenticate`, so the admin panel's login too), PATCH, both branches of `resolveTarget` (the non-admin
      self-comparison and the admin lookup), and the forgot-password lookup. Stored addresses are therefore
      always already normalized, so `users.email TEXT UNIQUE` catches a second signup for a differently-cased
      address; migration `000007_normalize_emails` lowercases and trims rows that predate the rule and fails
      loudly on `users_email_key` if two accounts differ only by case. `citext` was not needed.
- [ ] `login` returns `403 "account not verified"` for inactive users after a successful password check, which
      confirms a valid credential pair. Decide whether that leak is acceptable.
- [x] Session claims and password-change invalidation. Tokens carry `iss`/`aud` (the `sessionIssuer`/`sessionAudience`
      constants in `rest/user.go`) that `requireSession` enforces with `jwt.WithIssuer`/`jwt.WithAudience`, plus
      `iat` and a custom `epoch` claim. `users.session_epoch` (migration `000004_session_invalidation`) is bumped
      by `updateUser` whenever the password changes, and `requireSession` rejects a token whose `epoch` is absent
      or differs from the stored value — so a password change retires every session minted before it, including
      the caller's own. A counter rather than a timestamp because the signing key is shared through the database
      (more than one instance may serve a request) and JWT date claims have one-second resolution: a timestamp
      version rejected sessions minted in the same second as the change, which the live smoke test caught.
      Deploying this ends every session in circulation — old tokens carry no `aud`/`epoch` and fail parsing.
- [x] Refresh tokens. `POST /v1/login` answers `SessionResponse{session, refresh}`: the session is the 1h JWT
      above (`sessionTTL`), the refresh token is a 256-bit random value good for 30 days (`refreshTokenTTL`),
      stored only as a SHA-256 hash in `refresh_tokens` (migration `000005_refresh_tokens`, reversible) with the
      account's `session_epoch` at issue. `POST /v1/refresh` takes `{"refresh":"..."}` and exchanges it. The
      exchange is one `DELETE ... RETURNING` (`ConsumeRefreshToken`), so the token is consumed exactly once even under
      concurrent requests, and each exchange mints a fresh session and a fresh refresh token (rotation) — a copy
      that leaked cannot be replayed once the legitimate client uses the original. The row's `session_epoch` is
      compared against the account's current one, so a password change retires refresh tokens minted before it
      exactly as it retires sessions; deleting an account takes its tokens via `ON DELETE CASCADE`, and an
      inactive account cannot refresh. A refresh token outlives the session, which is the point: a client that
      was away for hours refreshes from the older session instead of logging in again. Tests in
      `rest/user_test.go` cover issuance, rotation, and every rejection path.
- [ ] Still open on sessions: no `jti`, so there is no logout endpoint and no per-session revocation of a live
      session — bumping `session_epoch` is only the whole-account version of that; spending a refresh token cuts
      off the refresh path but a session already minted lives out its hour. Expired `refresh_tokens` rows are
      purged by a daily janitor (`purgeExpiredTokens`) rather than only on presentation.

## P1 — schema and repository

- [x] `sql/password.sql` written: `CreatePasswordResetToken`, `ConsumePasswordResetToken` (a `DELETE ...
      RETURNING`, so redemption is single-use even under concurrent requests), `DeletePasswordResetTokensForUser`
      and `DeleteExpiredPasswordResetTokens`, against `password_reset_tokens` (migration `000006_password_reset`,
      reversible, hash stored, `ON DELETE CASCADE`). Wired to `POST /v1/password/forgot` (issues one token,
      clears the rest; generic `202` whether or not the address exists) and `POST /v1/password/reset` (sets a
      fresh salt/hash and bumps `session_epoch`, retiring every session and refresh token). The link is logged
      to the console because no email provider is configured, as with signup verification. Tests in
      `rest/user_test.go`.
- [x] Migration gaps: `000002_user_password.down.sql` now restores the NOT NULL columns (fails on rows still
      NULL — credentials must be repopulated before downgrading), and `000003_auth.down.sql` restores `username`
      as `NOT NULL UNIQUE` (`users_username_key`) and drops `signing_keys` as its `up` created it — the `up`
      dropped the column, so the values themselves are unrecoverable; the down restores the schema shape only.
      Verified: full `000001`→`000005` up then down cycle on a scratch database leaves zero tables, and after
      `000003.down` the `users` table matches `000001`'s shape.
- [ ] `hashed_password` and `salt` were made nullable in `000002_user_password.up.sql`, but `models.go` still
      emits non-pointer `[]byte` and `login` nil-checks `user.HashedPassword` and `user.Salt` to decide whether
      a usable credential exists. Add a nullable `bytea` override to `sqlc.yaml` or revert the migration.
- [ ] Generated-but-unused queries: `StoreUser`, `DeactivateUser`, `SetAdmin`, `DisableAdmin`,
      `DeleteVerificationToken`. (`DeleteUser`/`UpdateUser` are wired by the API handlers and `GetUsers`/
      `SearchUsers` by the admin panel.) `DeactivateUser`/`SetAdmin`/`DisableAdmin` are subsumed by
      `UpdateUser`'s whole-row write — delete them unless a narrower statement is wanted for each. Wire or
      delete the rest.
- [x] Expired token janitor: a daily `purgeExpiredTokens` goroutine deletes expired `refresh_tokens`,
      `verification_tokens` and `password_reset_tokens` (`expires_at < now()`), so abandoned signups and
      unconsumed refresh/reset tokens no longer accumulate. Failure is logged and retried on the next tick.
- [x] Signing key handling: `loadSigningKey` no longer generates a fresh secret each boot. It reads the
      `oidc_signing_key` row, creates one only when absent (`GetSigningKey`/`CreateSigningKey`,
      `sql/signing_key.sql`), and the `ON CONFLICT ... DO UPDATE` self-write is gone; `kid` is derived from
      the public key (RFC 7638) instead of stored. Rotation remains in the OIDC section.

## P1 — runtime

- [x] `main.go` uses `pgxpool` instead of a single `pgx.Connect`, so queries no longer serialize on one
      connection.
- [ ] `controller.Run` hardcodes `:8080` in `http.ListenAndServe` and `main` calls `log.Fatal(srv.Run())`:
      no address env var, no signal handling, no graceful shutdown.
- [ ] No `http.Server` timeouts (`ReadHeaderTimeout`, `ReadTimeout`, `IdleTimeout`) → slowloris exposure.
- [x] `signupPage` and the panel assets are embedded: `static.Files` uses `go:embed` and is served with
      `http.ServeFileFS` / `http.FileServerFS`, so the binary no longer depends on its working directory.
- [ ] No migration runner (no golang-migrate/goose); `migrations/*.sql` are applied by hand. Fold this into
      startup migrations below so a fresh instance is ready without hand-applying them.
- [ ] Add a second database provider (SQLite) behind the repository interface: dialect-specific queries, a
      driver alongside `pgx`, and `DATABASE_URL`-driven selection, with migrations run automatically on
      startup so a fresh instance is ready without hand-applying them.

## P2 — hygiene

- [ ] `README.md` documents the Podman dev container (e.g. `postgres-dev`); still to add `DATABASE_URL`,
      `LOGLEVEL`, `PUBLIC_BASE_URL`, the routes, and the migrate/run steps.
- [ ] `main_test.go` requires a live Postgres and defaults to `postgresql://postgres:postgres@localhost:5432`
      with no `t.Skip`, so any CI job needs a database service.
- [ ] No CI workflow and no Dockerfile.
- [ ] No API documentation (OpenAPI); error responses are inconsistent — some paths call
      `w.WriteHeader(...)` with an empty body, others use `PlainText`.
- [ ] Visibility is mixed: `New` returns the unexported `*controller` while `User`, `CreateUserRequest`,
      `LoginRequest` are exported.
- [ ] `static/signup.html` uses an inline `<script>`; plan a CSP (nonce or external file) before adding one.
- [ ] No client-IP or audit logging for failed logins and rejected verification tokens.

## P2 — admin panel

- [x] Admin panel: server-rendered templ components driven by htmx at `/admin` (`GET` list, `GET
      /admin/users` search fragment, `POST .../toggle-active`, `.../toggle-admin`, `.../delete`), all behind
      `requireSession` plus an admin check (`adminOnly`). `GetUsers`/`SearchUsers` back the list; actions reuse
      `UpdateUser`/`DeleteUser`. `requireSession` now also accepts a session cookie, and `/admin/login` +
      `/admin/logout` issue and clear it (HttpOnly, `SameSite=Lax`) so a browser can use the panel; the
      caller's own row renders no actions. Assets are embedded (see the go:embed item). Tests in
      `rest/admin_test.go`. Still open: a CSRF token beyond `SameSite=Lax`, pagination, and the signup page's
      inline script/CSP item below.
- [ ] Sessions admin page: list an account's live sessions (and refresh tokens) and let an admin invalidate
      one or all of them. Blocked on a per-session identifier (`jti`) or a server-side session inventory:
      today sessions are stateless JWTs, only `refresh_tokens` are stored, and `session_epoch` is the
      whole-account lever, so an individual live session cannot be revoked (see the P0 `jti` item).