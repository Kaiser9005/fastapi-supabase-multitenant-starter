# fastapi-supabase-multitenant-starter

**A multi-tenant SaaS skeleton where tenant isolation is a Postgres guarantee, not an app convention.**

The mistake most multi-tenant codebases make: scattering `where tenant_id = ...`
across application code, then leaking the day someone forgets one. This starter
puts isolation in the database with **Row-Level Security**, so the FastAPI layer
contains **zero tenant filters** — and *cannot* leak across tenants even if a query
is written carelessly.

## The pattern

1. **Two SECURITY DEFINER helpers** (`public.tenant_id()`, `public.is_super_admin()`)
   read the tenant from the caller's JWT. Every policy references the same two
   functions — you never hand-roll JWT parsing inside individual policies (that's
   the bug factory).
2. **Every tenant-scoped table** carries `tenant_id uuid not null default public.tenant_id()`
   — inserts are auto-stamped from the JWT, so app code can't send the wrong one.
3. **One canonical RLS policy** per table:
   ```sql
   using (tenant_id = public.tenant_id() or public.is_super_admin())
   with check (tenant_id = public.tenant_id())
   ```
4. **The API forwards the caller's JWT** to Supabase (anon key + `postgrest.auth(jwt)`),
   so PostgREST runs every query *as that user* and RLS scopes it. The **service-role
   key (which bypasses RLS) is never on a request path.**

See `migrations/0001_init_tenant_isolation.sql` — it also documents the three
broken tenant-resolution variants you should never copy, and shows the
shared-reference-table exception (no `tenant_id`, but RLS still required).

## Run it

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # fill SUPABASE_URL + SUPABASE_ANON_KEY

# apply the migration (Supabase CLI, or paste into the SQL editor):
supabase db push   # or: psql "$DATABASE_URL" -f migrations/0001_init_tenant_isolation.sql

uvicorn app.main:app --reload
```

```bash
# Every call needs a Supabase USER jwt; RLS scopes results to that user's tenant:
curl -H "Authorization: Bearer <user-jwt>" localhost:8000/widgets
curl -X POST -H "Authorization: Bearer <user-jwt>" -H "Content-Type: application/json" \
     -d '{"name":"sprocket","quantity":5}' localhost:8000/widgets
```

## Prove the isolation (the test that matters)

Mint two user JWTs in different tenants. Tenant A inserts a widget; tenant B's
`GET /widgets` does **not** see it, and `GET /widgets/{A_id}` returns 404 (not 403 —
RLS makes "not yours" and "doesn't exist" indistinguishable, which is the privacy
property you want). No app code enforces this; the database does.

## Mint `tenant_id` into the JWT

This starter reads `app_metadata.tenant_id` / `app_metadata.role` from the JWT.
Set them with a Supabase [custom access-token hook](https://supabase.com/docs/guides/auth/auth-hooks/custom-access-token-hook)
(or write them to `app_metadata` at signup). Adjust the claim path in
`public.tenant_id()` if you mint them elsewhere.

## License

MIT.
