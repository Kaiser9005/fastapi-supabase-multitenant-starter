-- =============================================================================
-- 0001_init_tenant_isolation.sql
-- Multi-tenant Row-Level Security baseline for Supabase / Postgres.
--
-- The pattern below is extracted (and generalized to a neutral `widgets` domain)
-- from a production multi-tenant SaaS. It is the CORRECT shape — the three
-- commonly-copied broken variants are listed at the bottom so you don't ship them.
-- =============================================================================

-- ─── 1. Tenant-resolution helpers ───────────────────────────────────────────
-- These read the tenant from the authenticated JWT. Centralizing them in two
-- SECURITY DEFINER functions means every policy references the SAME logic — you
-- never hand-roll `auth.jwt() ->> ...` inside individual policies (that's the bug
-- factory). Adjust the claim path to match how YOU mint tenant_id into the JWT
-- (Supabase: a custom access-token hook, or app_metadata.tenant_id).

create or replace function public.tenant_id()
returns uuid
language sql stable
security definer
set search_path = public
as $$
  -- Read tenant_id from the JWT's app_metadata (set via a Supabase access-token hook).
  select nullif(
    current_setting('request.jwt.claims', true)::jsonb
      -> 'app_metadata' ->> 'tenant_id',
    ''
  )::uuid;
$$;

create or replace function public.is_super_admin()
returns boolean
language sql stable
security definer
set search_path = public
as $$
  select coalesce(
    (current_setting('request.jwt.claims', true)::jsonb
      -> 'app_metadata' ->> 'role') = 'super_admin',
    false
  );
$$;

-- ─── 2. A tenant-scoped table ───────────────────────────────────────────────
create table if not exists public.widgets (
  id          uuid primary key default gen_random_uuid(),
  -- EVERY tenant-scoped table carries tenant_id with this default so inserts are
  -- auto-stamped from the caller's JWT (no app code can forget it).
  tenant_id   uuid not null default public.tenant_id(),
  name        text not null,
  quantity    integer not null default 0 check (quantity >= 0),
  created_at  timestamptz not null default now()
);

create index if not exists widgets_tenant_id_idx on public.widgets (tenant_id);

-- ─── 3. RLS: the canonical policy ───────────────────────────────────────────
alter table public.widgets enable row level security;

-- One FOR ALL policy. USING gates reads/updates/deletes; WITH CHECK gates writes
-- so a tenant can never insert/move a row into another tenant.
create policy "tenant_isolation" on public.widgets
  for all
  using (tenant_id = public.tenant_id() or public.is_super_admin())
  with check (tenant_id = public.tenant_id());

-- Defense-in-depth: RLS already blocks anon, but revoke explicitly too.
revoke all on public.widgets from anon;
grant select, insert, update, delete on public.widgets to authenticated;

-- ─── 4. Shared-reference table (NO tenant_id) — still needs RLS ─────────────
-- Reference data shared across tenants is the ONE column-level exception to the
-- tenant_id rule — but it MUST still enable RLS, or any anon JWT can mutate it.
create table if not exists public.widget_categories (
  id    uuid primary key default gen_random_uuid(),
  label text not null,
  is_active boolean not null default true
);

alter table public.widget_categories enable row level security;

create policy "ref_read_authenticated" on public.widget_categories
  for select to authenticated using (true);

create policy "ref_write_super_admin" on public.widget_categories
  for all to authenticated
  using (public.is_super_admin())
  with check (public.is_super_admin());

revoke insert, update, delete on public.widget_categories from anon;

-- =============================================================================
-- ❌ BROKEN PATTERNS — never use these for tenant resolution in a policy:
--    current_setting('app.tenant_id')          -- not set by Supabase auth
--    current_setting('rls.tenant_id')          -- ditto
--    (auth.jwt() ->> 'tenant_id')::uuid        -- bypasses the centralized helper;
--                                                 drifts per-policy, fails silently
-- Always go through public.tenant_id() / public.is_super_admin().
-- =============================================================================

-- ─── Rollback (manual) ───────────────────────────────────────────────────────
-- drop table if exists public.widgets cascade;
-- drop table if exists public.widget_categories cascade;
-- drop function if exists public.tenant_id();
-- drop function if exists public.is_super_admin();
