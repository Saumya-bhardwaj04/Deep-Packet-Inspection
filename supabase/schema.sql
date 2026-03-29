create table if not exists users (
  id bigserial primary key,
  username text unique not null,
  password text not null,
  role text not null default 'viewer',
  created_at timestamptz not null default now()
);

create table if not exists rules (
  id bigserial primary key,
  user_id text unique not null,
  blocked_ips jsonb not null default '[]'::jsonb,
  blocked_apps jsonb not null default '[]'::jsonb,
  blocked_domains jsonb not null default '[]'::jsonb,
  blocked_ports jsonb not null default '[]'::jsonb,
  updated_at timestamptz not null default now()
);

create table if not exists dpi_runs (
  id bigserial primary key,
  user_id text not null,
  input_file text not null,
  output_file text not null,
  run_type text not null default 'full',
  total_packets integer not null default 0,
  forwarded integer not null default 0,
  dropped integer not null default 0,
  drop_rate double precision not null default 0,
  top_apps jsonb not null default '{}'::jsonb,
  block_reasons jsonb not null default '{}'::jsonb,
  timestamp timestamptz not null default now()
);

create table if not exists access_requests (
  id bigserial primary key,
  username text not null,
  status text not null default 'pending',
  requested_at timestamptz not null default now(),
  reviewed_at timestamptz,
  reviewed_by text
);

create index if not exists idx_dpi_runs_user_time on dpi_runs(user_id, timestamp desc);
create index if not exists idx_access_requests_status_time on access_requests(status, requested_at desc);

alter table if exists dpi_runs
add column if not exists run_type text not null default 'full';
