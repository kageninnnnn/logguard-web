-- Cloud bot: run once in Supabase → SQL Editor (safe to run after schema_bot.sql).
create table if not exists public.bot_feedback (
  id bigint generated always as identity primary key,
  created_at timestamptz not null default now(),
  "user" text, source text, log text,
  ai_severity text, ai_is_threat boolean, ai_confidence text, latency_s numeric,
  user_verdict text, agree boolean
);
create table if not exists public.bot_surveys (
  id bigint generated always as identity primary key,
  created_at timestamptz not null default now(),
  "user" text,
  clarity int check (clarity between 1 and 5),
  fix int check (fix between 1 and 5),
  accuracy int check (accuracy between 1 and 5),
  use text, comment text
);
-- survey progress per chat (the serverless bot keeps no memory between requests)
create table if not exists public.bot_sessions (
  chat_id bigint primary key,
  step int not null default 0,
  answers jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);
alter table public.bot_feedback enable row level security;
alter table public.bot_surveys  enable row level security;
alter table public.bot_sessions enable row level security;
-- No anon policies needed: the bot uses the server-side secret key, which bypasses RLS.
drop policy if exists "bot insert" on public.bot_feedback;
drop policy if exists "bot insert" on public.bot_surveys;
revoke insert on public.bot_feedback, public.bot_surveys from anon;
