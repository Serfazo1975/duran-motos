-- DURAN MOTOS V21: roles reales, Log inalterable y stock controlado por la base.
-- No modifica ni borra datos existentes de dm_*.

-- 1) Roles por email (sin acceso desde el navegador: solo lo leen las funciones)
create table if not exists public.dm_roles (
  email text primary key,
  role  text not null check (role in ('admin','operador'))
);
alter table public.dm_roles enable row level security;
revoke all on public.dm_roles from anon, authenticated;
insert into public.dm_roles(email, role) values
  ('admin@duranmotos.ar','admin'),
  ('sergiofazzini@gmail.com','admin'),
  ('operador@duranmotos.ar','operador')
on conflict (email) do nothing;

-- 2) Ajustes internos (interruptor de control estricto). Arranca APAGADO.
create table if not exists public.dm_settings (
  key text primary key,
  value jsonb not null default '{}'::jsonb
);
alter table public.dm_settings enable row level security;
revoke all on public.dm_settings from anon, authenticated;
insert into public.dm_settings(key, value) values ('enforce_roles', '{"on": false}')
on conflict (key) do nothing;

-- 3) Log de movimientos: solo se agrega, solo lo lee el administrador
create table if not exists public.dm_log (
  id bigint generated always as identity primary key,
  ts timestamptz not null default now(),
  user_email text,
  role text,
  category text not null,
  type text not null,
  product_id bigint,
  product_code text,
  product_name text,
  qty numeric not null default 0,
  stock_after numeric,
  detail text,
  repair_id bigint
);
create index if not exists dm_log_ts_idx on public.dm_log (ts desc);
alter table public.dm_log enable row level security;
revoke all on public.dm_log from anon, authenticated;
grant select on public.dm_log to authenticated;

-- 4) Rol actual (autoritativo, sale del token de sesión)
create or replace function public.dm_current_role() returns text
language sql stable security definer set search_path = public as $$
  select case
    when auth.uid() is null then 'system'
    else coalesce((select r.role from public.dm_roles r where lower(r.email) = lower(auth.jwt()->>'email')), 'operador')
  end
$$;

create or replace function public.dm_enforced() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select (value->>'on')::boolean from public.dm_settings where key = 'enforce_roles'), false)
$$;

create policy "admin lee el log" on public.dm_log
  for select to authenticated using (public.dm_current_role() = 'admin');

-- Escritura interna del log
create or replace function public.dm_write_log(
  p_category text, p_type text, p_product_id bigint, p_code text, p_name text,
  p_qty numeric, p_stock_after numeric, p_detail text, p_repair bigint default null
) returns void language plpgsql security definer set search_path = public as $$
begin
  insert into public.dm_log(user_email, role, category, type, product_id, product_code, product_name, qty, stock_after, detail, repair_id)
  values (coalesce(auth.jwt()->>'email','sistema'), public.dm_current_role(), p_category, p_type, p_product_id, p_code, p_name,
          coalesce(p_qty,0), p_stock_after, left(coalesce(p_detail,''), 500), p_repair);
end $$;

-- 5) Guardia sobre productos
create or replace function public.dm_products_guard() returns trigger
language plpgsql security definer set search_path = public as $$
declare
  r text := public.dm_current_role();
  enf boolean := public.dm_enforced();
  via_rpc boolean := coalesce(nullif(current_setting('dm.rpc', true), ''), '') = '1';
  os numeric; ns numeric; nd jsonb;
begin
  if r = 'system' then
    if tg_op = 'DELETE' then return old; else return new; end if;
  end if;

  if tg_op = 'INSERT' then
    if exists (select 1 from public.dm_products where id = new.id) then return new; end if; -- upsert sobre fila existente
    if r = 'operador' and enf then
      perform public.dm_write_log('stock','denegado', new.id, new.data->>'code', new.data->>'name', 0, null, 'El Operador intentó crear un producto');
      return null;
    end if;
    perform public.dm_write_log('stock','alta', new.id, new.data->>'code', new.data->>'name',
            coalesce((new.data->>'stock')::numeric,0), coalesce((new.data->>'stock')::numeric,0), 'Producto nuevo');
    return new;
  end if;

  if tg_op = 'DELETE' then
    if r = 'operador' and enf then
      perform public.dm_write_log('stock','denegado', old.id, old.data->>'code', old.data->>'name', 0, null, 'El Operador intentó eliminar un producto');
      return null;
    end if;
    perform public.dm_write_log('stock','baja', old.id, old.data->>'code', old.data->>'name',
            -coalesce((old.data->>'stock')::numeric,0), 0, 'Producto eliminado');
    return old;
  end if;

  -- UPDATE
  if via_rpc then return new; end if;  -- lo registra la función de stock
  os := coalesce((old.data->>'stock')::numeric, 0);
  ns := coalesce((new.data->>'stock')::numeric, 0);

  if r = 'operador' and enf then
    -- El Operador no puede cambiar nada por esta vía: se conserva siempre el dato del servidor
    new.data := old.data;
    return new;
  end if;

  if ns <> os then
    perform public.dm_write_log('stock',
      case when r = 'admin' then 'ajuste' else 'cambio_stock' end,
      new.id, new.data->>'code', new.data->>'name', ns - os, ns,
      'Cambio de stock ' || os || ' → ' || ns);
  end if;
  if (old.data - 'stock') is distinct from (new.data - 'stock') then
    perform public.dm_write_log('stock','edicion', new.id, new.data->>'code', new.data->>'name', 0, ns, 'Producto modificado');
  end if;
  return new;
end $$;

drop trigger if exists dm_products_guard_trg on public.dm_products;
create trigger dm_products_guard_trg
  before insert or update or delete on public.dm_products
  for each row execute function public.dm_products_guard();

-- 6) Operaciones de stock (única vía del Operador)
create or replace function public.dm_stock_in(p_product bigint, p_qty int, p_note text default null)
returns jsonb language plpgsql security definer set search_path = public as $$
declare cur numeric; nw numeric; d jsonb;
begin
  if auth.uid() is null then raise exception 'No autenticado'; end if;
  if p_qty is null or p_qty < 1 or p_qty > 100000 then
    return jsonb_build_object('ok', false, 'error', 'Cantidad inválida');
  end if;
  select data into d from public.dm_products where id = p_product for update;
  if not found then return jsonb_build_object('ok', false, 'error', 'Producto no encontrado'); end if;
  cur := coalesce((d->>'stock')::numeric, 0);
  nw := cur + p_qty;
  perform set_config('dm.rpc', '1', true);
  update public.dm_products set data = jsonb_set(data, '{stock}', to_jsonb(nw)), updated_at = now() where id = p_product;
  perform set_config('dm.rpc', '', true);
  perform public.dm_write_log('stock','ingreso', p_product, d->>'code', d->>'name', p_qty, nw,
          'Ingreso de stock' || case when coalesce(p_note,'') <> '' then ': ' || p_note else '' end, null);
  return jsonb_build_object('ok', true, 'stock', nw);
end $$;

-- Descuento atómico (todo o nada). p_category: 'venta' | 'taller'
create or replace function public.dm_consume_stock(p_items jsonb, p_category text, p_detail text default null, p_repair bigint default null)
returns jsonb language plpgsql security definer set search_path = public as $$
declare it jsonb; d jsonb; cur numeric; q numeric; pid bigint; res jsonb := '{}'::jsonb; typ text;
begin
  if auth.uid() is null then raise exception 'No autenticado'; end if;
  if p_category not in ('venta','taller') then raise exception 'Categoría inválida'; end if;
  typ := case when p_category = 'taller' then 'consumo' else 'venta' end;

  -- 1) verificar todo antes de descontar
  for it in select * from jsonb_array_elements(p_items) loop
    pid := (it->>'id')::bigint; q := (it->>'qty')::numeric;
    if q is null or q < 1 or q <> trunc(q) or q > 100000 then
      return jsonb_build_object('ok', false, 'error', 'Cantidad inválida');
    end if;
    select data into d from public.dm_products where id = pid for update;
    if not found then return jsonb_build_object('ok', false, 'error', 'Producto no encontrado', 'product', pid); end if;
    cur := coalesce((d->>'stock')::numeric, 0);
    if cur < q then
      perform public.dm_write_log(p_category, case when p_category='taller' then 'consumo_rechazado' else 'venta_rechazada' end,
              pid, d->>'code', d->>'name', -q, cur, 'Stock insuficiente (disponible ' || cur || '). ' || coalesce(p_detail,''), p_repair);
      return jsonb_build_object('ok', false, 'error', 'Stock insuficiente', 'product', pid, 'name', d->>'name', 'available', cur);
    end if;
  end loop;

  -- 2) descontar y registrar
  perform set_config('dm.rpc', '1', true);
  for it in select * from jsonb_array_elements(p_items) loop
    pid := (it->>'id')::bigint; q := (it->>'qty')::numeric;
    select data into d from public.dm_products where id = pid;
    cur := coalesce((d->>'stock')::numeric, 0) - q;
    update public.dm_products set data = jsonb_set(data, '{stock}', to_jsonb(cur)), updated_at = now() where id = pid;
    perform public.dm_write_log(p_category, typ, pid, d->>'code', d->>'name', -q, cur, p_detail, p_repair);
    res := res || jsonb_build_object(pid::text, cur);
  end loop;
  perform set_config('dm.rpc', '', true);
  return jsonb_build_object('ok', true, 'stocks', res);
end $$;

-- Devolución al stock (solo administrador)
create or replace function public.dm_return_stock(p_product bigint, p_qty int, p_repair bigint, p_detail text default null)
returns jsonb language plpgsql security definer set search_path = public as $$
declare d jsonb; nw numeric;
begin
  if public.dm_current_role() <> 'admin' then
    perform public.dm_write_log('sistema','denegado', null, null, null, 0, null, 'Intento de devolver insumo sin ser administrador', p_repair);
    return jsonb_build_object('ok', false, 'error', 'Solo el administrador');
  end if;
  if p_qty is null or p_qty < 1 then return jsonb_build_object('ok', false, 'error', 'Cantidad inválida'); end if;
  select data into d from public.dm_products where id = p_product for update;
  if not found then return jsonb_build_object('ok', true, 'stock', null, 'missing', true); end if;
  nw := coalesce((d->>'stock')::numeric,0) + p_qty;
  perform set_config('dm.rpc', '1', true);
  update public.dm_products set data = jsonb_set(data, '{stock}', to_jsonb(nw)), updated_at = now() where id = p_product;
  perform set_config('dm.rpc', '', true);
  perform public.dm_write_log('taller','devolucion', p_product, d->>'code', d->>'name', p_qty, nw, p_detail, p_repair);
  return jsonb_build_object('ok', true, 'stock', nw);
end $$;

-- Eventos de taller / sesión desde la app (lista cerrada, no se pueden falsificar movimientos de stock)
create or replace function public.dm_log_event(p_type text, p_detail text, p_repair bigint default null)
returns void language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'No autenticado'; end if;
  if p_type in ('reparacion_alta','estado') then
    perform public.dm_write_log('taller', p_type, null, null, null, 0, null, p_detail, p_repair);
  elsif p_type in ('login','logout','backup','restauracion','importacion') then
    perform public.dm_write_log('sistema', p_type, null, null, null, 0, null, p_detail, null);
  else
    raise exception 'Tipo de evento no permitido';
  end if;
end $$;

-- Interruptor de control estricto (solo administrador)
create or replace function public.dm_set_enforcement(p_on boolean) returns jsonb
language plpgsql security definer set search_path = public as $$
begin
  if public.dm_current_role() <> 'admin' then return jsonb_build_object('ok', false, 'error', 'Solo el administrador'); end if;
  update public.dm_settings set value = jsonb_build_object('on', p_on) where key = 'enforce_roles';
  perform public.dm_write_log('sistema','control_estricto', null, null, null, 0, null,
          case when p_on then 'Control estricto del Operador ACTIVADO' else 'Control estricto del Operador DESACTIVADO' end, null);
  return jsonb_build_object('ok', true, 'on', p_on);
end $$;

create or replace function public.dm_status() returns jsonb
language sql stable security definer set search_path = public as $$
  select jsonb_build_object('role', public.dm_current_role(), 'enforced', public.dm_enforced())
$$;

-- Permisos de ejecución: solo usuarios con sesión
revoke all on function public.dm_current_role(), public.dm_enforced(), public.dm_write_log(text,text,bigint,text,text,numeric,numeric,text,bigint),
  public.dm_stock_in(bigint,int,text), public.dm_consume_stock(jsonb,text,text,bigint), public.dm_return_stock(bigint,int,bigint,text),
  public.dm_log_event(text,text,bigint), public.dm_set_enforcement(boolean), public.dm_status(), public.dm_products_guard()
  from public, anon, authenticated;
grant execute on function public.dm_stock_in(bigint,int,text), public.dm_consume_stock(jsonb,text,text,bigint),
  public.dm_return_stock(bigint,int,bigint,text), public.dm_log_event(text,text,bigint),
  public.dm_set_enforcement(boolean), public.dm_status() to authenticated;
-- la política del log invoca dm_current_role en nombre del usuario
grant execute on function public.dm_current_role() to authenticated;
