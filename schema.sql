create table if not exists users (
  id bigserial primary key,
  category text not null,
  role text not null,
  name text default '',
  username text unique not null,
  password_hash text not null,
  notes text default ''
);
create table if not exists subjects (
  id bigserial primary key,
  subject_code text unique not null,
  subject_name text not null,
  lic text default '',
  lic_start text default '',
  lic_end text default '',
  rp text default '',
  rp_start text default '',
  rp_end text default ''
);
create table if not exists files (
  id bigserial primary key,
  subject_code text not null,
  uploader_username text not null,
  role text not null,
  doc_type text not null,
  semester text not null,
  url text not null,
  sha256 text not null,
  uploaded_at timestamp default now()
);
