-- LogGuard bot: user-testing data. Run once in Supabase → SQL Editor.
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
alter table public.bot_feedback enable row level security;
alter table public.bot_surveys  enable row level security;
-- the bot may only INSERT; reading is done by the team in the Supabase dashboard
drop policy if exists "bot insert" on public.bot_feedback;
create policy "bot insert" on public.bot_feedback for insert to anon with check (true);
drop policy if exists "bot insert" on public.bot_surveys;
create policy "bot insert" on public.bot_surveys for insert to anon with check (true);
grant insert on public.bot_feedback, public.bot_surveys to anon;
