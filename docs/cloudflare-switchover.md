# Cloudflare switchover runbook

This runbook covers the production-only steps after the Cloudflare branch has
passed its local release gate. Nothing in `npm run validate:cloudflare`
creates account resources or deploys code.

## 1. Preconditions

- Confirm the intended release commit on the `cloudflare` branch.
- Preserve the current Python origin and its routing configuration for rollback.
- Confirm the production values in `wrangler.jsonc`, especially the Worker
  name, R2 bucket name, Durable Object binding/migration, limits, and TTL.
- Confirm the Cloudflare account/profile selected by Wrangler.
- Run the immutable local gate:

  ```sh
  npm ci
  npm run validate:cloudflare
  ```

- Record the test summary and dry-run bundle size with the release.

## 2. Provision the private R2 bucket

These commands mutate the selected Cloudflare account and require explicit
production approval:

```sh
npx wrangler r2 bucket create drop5-files
npx wrangler r2 bucket lifecycle set drop5-files --file scripts/r2-lifecycle.json
npx wrangler r2 bucket lifecycle list drop5-files
```

The bucket must stay private. The rules in `scripts/r2-lifecycle.json` apply to
all object prefixes and are a safety net for orphaned objects only: objects and
incomplete multipart uploads expire after 10 minutes, one TTL beyond the
authoritative five-minute Durable Object alarm. Durable Object alarms remain
the authoritative five-minute deletion mechanism. R2 lifecycle expiration runs
on a periodic sweep, so actual deletion can lag the 10-minute mark; anything
still present is unbillable once the sweep removes it, and the free tier covers
the transient orphans at this service's scale.

If the lifecycle rule already exists, inspect it with `lifecycle list` rather
than adding a duplicate. To manage the complete lifecycle configuration from a
reviewed JSON file, use:

```sh
npx wrangler r2 bucket lifecycle set drop5-files < lifecycle.json
```

## 3. Edge controls

Before accepting public traffic:

- Add a rate limit for session creation.
- Add a separate rate limit for upload routes.
- Keep the R2 bucket inaccessible from a public bucket URL.
- Verify the Worker route is the only public path to downloads.
- Confirm WAF rules do not block WebSocket upgrades or legitimate multipart
  uploads up to the configured 30 MB per-file limit.

## 4. Deploy and canary

Only after production approval:

```sh
npm run deploy
```

Use the Worker preview/assigned hostname before changing production traffic.
Verify:

1. `GET /` redirects to a random session.
2. Korean `Accept-Language` returns `Content-Language: ko`, a Korean UI, and
   Korean structured errors; an unsupported language falls back to English.
3. A host joins, a second device remains pending, and approval succeeds.
4. Browser multipart, JSON text, and iOS Shortcut uploads all succeed.
5. Listing and downloading return the original bytes and Unicode filename.
6. An unapproved client cannot list or download files.
7. WebSocket notifications survive Durable Object hibernation.
8. Manual delete removes metadata and R2 objects.
9. The five-minute alarm removes expired metadata and R2 objects.
10. A file over the limit returns HTTP 413 with a per-file list and no R2 write.

## 5. Traffic switchover

- Lower DNS TTL in advance if DNS, rather than a Worker route, controls traffic.
- Route a small canary share of traffic to the Worker if the zone setup permits.
- Watch Worker exceptions, Durable Object errors, R2 operation errors, 4xx/5xx
  rates, WebSocket failures, and upload latency.
- Move all traffic only after the canary checks remain clean.
- Keep the Python origin intact until the rollback window closes.

## 6. Rollback

If correctness, security, or availability regresses:

1. Restore the previous route/DNS target to the Python service.
2. Do not delete the Worker, Durable Object namespace, or R2 bucket while
   requests or rollback analysis may still reference them.
3. Keep the lifecycle safety rule enabled so orphaned objects expire.
4. Capture the failing request, Worker logs, release commit, and rollback time.
5. Fix and repeat the complete precondition and canary gates before retrying.

Rollback changes traffic only; it must not attempt to migrate active ephemeral
sessions between implementations.
