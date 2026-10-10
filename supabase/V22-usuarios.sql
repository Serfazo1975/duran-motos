-- DURAN MOTOS V22: usuarios compartidos entre todos los dispositivos.
-- Aditivo: no modifica ni borra datos. Requiere haber aplicado la migración V21.

create table if not exists public.dm_users (
  username text primary key check (username ~ '^[a-z0-9._-]{2,30}$'),
  email    text not null unique,
  name     text not null,
  created_at timestamptz not null default now()
);
alter table public.dm_users enable row level security;
revoke all on public.dm_users from anon, authenticated;

-- Usuarios que ya existen
insert into public.dm_users(username, email, name) values
  ('admin',    'admin@duranmotos.ar',    'Administrador'),
  ('operador', 'operador@duranmotos.ar', 'Operador'),
  ('sergio',   'sergiofazzini@gmail.com','Sergio')
on conflict (username) do nothing;

-- Antes del login: devuelve solo el email de ese usuario (no el rol ni datos)
create or replace function public.dm_resolve_user(p_username text) returns text
language sql stable security definer set search_path = public as $$
  select email from public.dm_users where username = lower(trim(p_username))
$$;

-- Quién soy (después del login)
create or replace function public.dm_whoami() returns jsonb
language sql stable security definer set search_path = public as $$
  select jsonb_build_object('username', u.username, 'name', u.name, 'role', public.dm_current_role(), 'email', u.email)
  from public.dm_users u where lower(u.email) = lower(auth.jwt()->>'email')
$$;

-- Lista de usuarios (solo administrador)
create or replace function public.dm_list_users() returns jsonb
language plpgsql stable security definer set search_path = public as $$
begin
  if public.dm_current_role() <> 'admin' then return '[]'::jsonb; end if;
  return coalesce((select jsonb_agg(jsonb_build_object('username', u.username, 'name', u.name, 'email', u.email,
            'role', coalesce(r.role,'operador')) order by u.created_at, u.username)
          from public.dm_users u left join public.dm_roles r on lower(r.email) = lower(u.email)), '[]'::jsonb);
end $$;

-- Alta (la cuenta de acceso se crea en el navegador del administrador; esto registra usuario y rol)
create or replace function public.dm_register_user(p_username text, p_name text, p_role text, p_email text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare u text := lower(trim(p_username));
begin
  if public.dm_current_role() <> 'admin' then return jsonb_build_object('ok', false, 'error', 'Solo el administrador'); end if;
  if p_role not in ('admin','operador') then return jsonb_build_object('ok', false, 'error', 'Rol inválido'); end if;
  if u !~ '^[a-z0-9._-]{2,30}$' then return jsonb_build_object('ok', false, 'error', 'Usuario inválido (2-30 letras, números, . _ -)'); end if;
  if coalesce(trim(p_name),'') = '' then return jsonb_build_object('ok', false, 'error', 'Falta el nombre'); end if;
  if exists (select 1 from public.dm_users where username = u) then return jsonb_build_object('ok', false, 'error', 'Ese usuario ya existe'); end if;
  insert into public.dm_users(username, email, name) values (u, lower(trim(p_email)), left(trim(p_name), 60));
  insert into public.dm_roles(email, role) values (lower(trim(p_email)), p_role)
    on conflict (email) do update set role = excluded.role;
  perform public.dm_write_log('sistema','usuario_alta', null, null, null, 0, null, 'Usuario creado: ' || u || ' (' || p_role || ')');
  return jsonb_build_object('ok', true);
end $$;

-- Cambiar nombre / rol (solo administrador; nunca deja el sistema sin administradores)
create or replace function public.dm_update_user(p_username text, p_name text, p_role text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare u public.dm_users; admins int;
begin
  if public.dm_current_role() <> 'admin' then return jsonb_build_object('ok', false, 'error', 'Solo el administrador'); end if;
  if p_role not in ('admin','operador') then return jsonb_build_object('ok', false, 'error', 'Rol inválido'); end if;
  select * into u from public.dm_users where username = lower(trim(p_username));
  if not found then return jsonb_build_object('ok', false, 'error', 'Usuario no encontrado'); end if;
  if p_role <> 'admin' then
    if lower(u.email) = lower(auth.jwt()->>'email') then return jsonb_build_object('ok', false, 'error', 'No podés quitarte a vos mismo el rol de administrador'); end if;
    select count(*) into admins from public.dm_users x join public.dm_roles r on lower(r.email)=lower(x.email)
      where r.role='admin' and x.username <> u.username;
    if admins = 0 then return jsonb_build_object('ok', false, 'error', 'Debe quedar al menos un administrador'); end if;
  end if;
  update public.dm_users set name = left(trim(p_name),60) where username = u.username;
  insert into public.dm_roles(email, role) values (lower(u.email), p_role)
    on conflict (email) do update set role = excluded.role;
  perform public.dm_write_log('sistema','usuario_edicion', null, null, null, 0, null, 'Usuario modificado: ' || u.username || ' (' || p_role || ')');
  return jsonb_build_object('ok', true);
end $$;

-- Baja (el usuario deja de poder ingresar por la app). No se puede eliminar a uno mismo ni al último administrador.
create or replace function public.dm_delete_user(p_username text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare u public.dm_users; admins int;
begin
  if public.dm_current_role() <> 'admin' then return jsonb_build_object('ok', false, 'error', 'Solo el administrador'); end if;
  select * into u from public.dm_users where username = lower(trim(p_username));
  if not found then return jsonb_build_object('ok', false, 'error', 'Usuario no encontrado'); end if;
  if lower(u.email) = lower(auth.jwt()->>'email') then return jsonb_build_object('ok', false, 'error', 'No podés eliminar tu propio usuario'); end if;
  select count(*) into admins from public.dm_users x join public.dm_roles r on lower(r.email)=lower(x.email)
    where r.role='admin' and x.username <> u.username;
  if admins = 0 then return jsonb_build_object('ok', false, 'error', 'Debe quedar al menos un administrador'); end if;
  delete from public.dm_users where username = u.username;
  delete from public.dm_roles where lower(email) = lower(u.email);
  perform public.dm_write_log('sistema','usuario_baja', null, null, null, 0, null, 'Usuario eliminado: ' || u.username);
  return jsonb_build_object('ok', true);
end $$;

revoke all on function public.dm_resolve_user(text), public.dm_whoami(), public.dm_list_users(),
  public.dm_register_user(text,text,text,text), public.dm_update_user(text,text,text), public.dm_delete_user(text)
  from public, anon, authenticated;
grant execute on function public.dm_resolve_user(text) to anon, authenticated;
grant execute on function public.dm_whoami(), public.dm_list_users(),
  public.dm_register_user(text,text,text,text), public.dm_update_user(text,text,text), public.dm_delete_user(text) to authenticated;
