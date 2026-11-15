-- LogGuard database schema. Run once in Supabase → SQL Editor → New query → Run.

create extension if not exists pgcrypto;

-- Company profile, created automatically on sign-up (7-day free trial)
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  company text,
  trial_ends_at timestamptz not null default now() + interval '7 days',
  created_at timestamptz not null default now()
);

-- Agents (servers) connected by a company
create table if not exists public.agents (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  name text not null,
  agent_key uuid not null unique default gen_random_uuid(),
  last_seen timestamptz,
  created_at timestamptz not null default now()
);

-- Alerts produced by AI triage
create table if not exists public.alerts (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  agent_id uuid references public.agents(id) on delete cascade,
  severity text not null check (severity in ('LOW','MEDIUM','HIGH','CRITICAL')),
  title text not null,
  explanation text,
  remediation text,
  raw_log text,
  status text not null default 'open' check (status in ('open','resolved')),
  created_at timestamptz not null default now()
);

alter table public.profiles enable row level security;
alter table public.agents   enable row level security;
alter table public.alerts   enable row level security;

drop policy if exists "own profile" on public.profiles;
create policy "own profile" on public.profiles for all using (auth.uid() = id) with check (auth.uid() = id);

drop policy if exists "own agents" on public.agents;
create policy "own agents" on public.agents for all using (auth.uid() = user_id) with check (auth.uid() = user_id);

drop policy if exists "own alerts" on public.alerts;
create policy "own alerts" on public.alerts for all using (auth.uid() = user_id) with check (auth.uid() = user_id);

-- Auto-create profile on sign-up
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, company) values (new.id, new.raw_user_meta_data->>'company');
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- Agent ingestion endpoint: the Python agent calls this with its agent_key.
create or replace function public.ingest_alert(
  p_agent_key uuid, p_severity text, p_title text,
  p_explanation text, p_remediation text, p_raw_log text
) returns bigint
language plpgsql security definer set search_path = public as $$
declare a record; new_id bigint;
begin
  select id, user_id into a from public.agents where agent_key = p_agent_key;
  if a.id is null then raise exception 'invalid agent key'; end if;
  update public.agents set last_seen = now() where id = a.id;
  insert into public.alerts (user_id, agent_id, severity, title, explanation, remediation, raw_log)
  values (a.user_id, a.id, upper(p_severity), left(p_title, 200), p_explanation, p_remediation, p_raw_log)
  returning id into new_id;
  return new_id;
end $$;

revoke all on function public.ingest_alert(uuid,text,text,text,text,text) from public;
grant execute on function public.ingest_alert(uuid,text,text,text,text,text) to anon, authenticated;

-- Live updates in the dashboard
alter publication supabase_realtime add table public.alerts;
