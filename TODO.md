# TODO

State as of the current working tree (builds clean, `go vet` clean, `go test ./...` green against a local Postgres).
Ordered by priority; every item is grounded in the code as it stands.

## Landed

- [x] `argon2` extraction finished: `rest/user.go` derives through the package-level
      `argon2.GenerateSalt/HashPassword/Validate`, `main_test.go` uses `argon2.NewDefaultArgon2id()`.
- [x] The relocation (generated `signing_key`/`verification_token` queries, `sql/`, `static/`, session
      validation) is committed in `2342a24`; the working tree is clean apart from this file.
- [x] `sqlc generate` reproduces the checked-in tree unchanged (`sqlc v1.31.1`).

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
- [ ] `users.email` is `TEXT UNIQUE` with no normalization: `Foo@x.com` and `foo@x.com` are distinct accounts
      and the unique index will not catch it. Normalize on write/read or use `citext`.
- [ ] `login` returns `403 "account not verified"` for inactive users after a successful password check, which
      confirms a valid credential pair. Decide whether that leak is acceptable.
- [ ] Sessions are 1h HS256 JWTs with no `jti`, issuer or audience, and there is no logout or refresh path and
      no revocation list.

## P1 — schema and repository

- [ ] `sql/password.sql` is empty — delete it or write the password-reset queries it was left for.
- [ ] Migration gaps: `000002_user_password.down.sql` is empty (non-reversible), and `000003_auth.down.sql`
      re-adds `username` even though `000003_auth.up.sql` drops it — a `down`/`up` round trip does not restore
      the `000001` schema.
- [ ] `hashed_password` and `salt` were made nullable in `000002_user_password.up.sql`, but `models.go` still
      emits non-pointer `[]byte` and `login` nil-checks `user.HashedPassword` and `user.Salt` to decide whether
      a usable credential exists. Add a nullable `bytea` override to `sqlc.yaml` or revert the migration.
- [ ] Generated-but-unused queries: `GetUsers`, `StoreUser`, `DeactivateUser`, `SetAdmin`, `DisableAdmin`,
      `DeleteVerificationToken`. (`DeleteUser` and `UpdateUser` are wired now: the delete/update handlers call
      them.) `DeactivateUser`/`SetAdmin`/`DisableAdmin` are subsumed by `UpdateUser`'s whole-row write — delete
      them unless a narrower statement is wanted for each. Wire or delete the rest.
- [ ] Expired `verification_tokens` are only cleaned up when the address is redeemed; abandoned signups
      accumulate forever. Add a janitor or an `expires_at` index plus periodic sweep.
- [ ] Signing key handling: `loadSigningKey` generates 32 random bytes on every boot and relies on
      `GetOrCreateSigningKey`'s `ON CONFLICT ... DO UPDATE`. There is no `kid`/rotation versioning; simplify the
      upsert to `DO NOTHING RETURNING`.

## P1 — runtime

- [ ] `main.go` opens a single `pgx.Connect`, so every request serializes on one connection. Switch to
      `pgxpool`.
- [ ] `controller.Run` hardcodes `:8080` in `http.ListenAndServe` and `main` calls `log.Fatal(srv.Run())`:
      no address env var, no signal handling, no graceful shutdown.
- [ ] No `http.Server` timeouts (`ReadHeaderTimeout`, `ReadTimeout`, `IdleTimeout`) → slowloris exposure.
- [ ] `signupPage` does `http.ServeFile(w, r, "static/signup.html")`, which breaks when the binary starts from
      any other directory. Use `go:embed`.
- [ ] No migration runner (no golang-migrate/goose); `migrations/*.sql` are applied by hand.

## P2 — hygiene

- [ ] `README.md` is empty. Document `DATABASE_URL`, `LOGLEVEL`, `PUBLIC_BASE_URL`, the routes, and the
      migrate/run steps.
- [ ] `main_test.go` requires a live Postgres and defaults to `postgresql://postgres:postgres@localhost:5432`
      with no `t.Skip`, so any CI job needs a database service.
- [ ] No CI workflow and no Dockerfile.
- [ ] No API documentation (OpenAPI); error responses are inconsistent — some paths call
      `w.WriteHeader(...)` with an empty body, others use `PlainText`.
- [ ] Visibility is mixed: `New` returns the unexported `*controller` while `User`, `CreateUserRequest`,
      `LoginRequest` are exported.
- [ ] `static/signup.html` uses an inline `<script>`; plan a CSP (nonce or external file) before adding one.
- [ ] No client-IP or audit logging for failed logins and rejected verification tokens.