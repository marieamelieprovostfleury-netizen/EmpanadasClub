-- À exécuter UNE fois dans Supabase > SQL Editor (après avoir sauvegardé vos données).
-- Rôles : 'admin' = Manager (tous les droits) · 'manager' = Responsable (saisie des stocks uniquement).

create or replace function public.stk_role() returns text
language sql stable security definer set search_path=public as
$$ select role from public.stk_profiles where id = auth.uid() $$;

-- Ventes réellement constatées : baisses de stock entre relevés successifs (90 derniers jours)
create or replace view public.stk_obs with (security_invoker=true) as
with r as (
  select store_id, product_id, qty, created_at,
         lag(qty) over (partition by store_id, product_id order by created_at) as pq
  from public.stk_readings where created_at > now() - interval '90 days')
select store_id, product_id,
       coalesce(sum(greatest(pq - qty, 0)),0)::float8 as sold,
       (extract(epoch from (max(created_at) - min(created_at)))/86400)::float8 as days
from r group by store_id, product_id;
grant select on public.stk_obs to authenticated;

-- Suppression complète d'un compte (réservé au Manager)
create or replace function public.stk_delete_user(p_id uuid) returns void
language plpgsql security definer set search_path=public as $$
begin
  if public.stk_role() is distinct from 'admin' then raise exception 'Droits insuffisants'; end if;
  if p_id = auth.uid() then raise exception 'Impossible de supprimer son propre compte'; end if;
  delete from public.stk_requests where user_id = p_id;
  delete from public.stk_profiles where id = p_id;
  delete from auth.users where id = p_id;
end $$;
revoke all on function public.stk_delete_user(uuid) from public, anon;
grant execute on function public.stk_delete_user(uuid) to authenticated;

-- Politiques d'accès : on remplace les anciennes
do $$ declare r record; begin
  for r in select policyname, tablename from pg_policies
           where schemaname='public' and tablename in
           ('stk_stores','stk_products','stk_lines','stk_periods','stk_readings','stk_profiles','stk_requests')
  loop execute format('drop policy %I on public.%I', r.policyname, r.tablename); end loop;
end $$;

do $$ declare t text; begin
  foreach t in array array['stk_stores','stk_products','stk_lines','stk_periods','stk_readings','stk_profiles','stk_requests'] loop
    execute format('alter table public.%I enable row level security', t);
  end loop;
  -- Manager : tout. Responsable : lecture des données de référence.
  foreach t in array array['stk_stores','stk_products','stk_lines','stk_periods'] loop
    execute format('create policy "%1$s_owner" on public.%1$s for all to authenticated using (public.stk_role()=''admin'') with check (public.stk_role()=''admin'')', t);
    execute format('create policy "%1$s_read" on public.%1$s for select to authenticated using (public.stk_role() is not null)', t);
  end loop;
end $$;

create policy stk_readings_owner on public.stk_readings for all to authenticated
  using (public.stk_role()='admin') with check (public.stk_role()='admin');
create policy stk_readings_read on public.stk_readings for select to authenticated
  using (public.stk_role() in ('admin','manager'));
create policy stk_readings_insert on public.stk_readings for insert to authenticated
  with check (public.stk_role() is not null);

create policy stk_profiles_owner on public.stk_profiles for all to authenticated
  using (public.stk_role()='admin') with check (public.stk_role()='admin');
create policy stk_profiles_self on public.stk_profiles for select to authenticated using (id = auth.uid());

create policy stk_requests_owner on public.stk_requests for all to authenticated
  using (public.stk_role()='admin') with check (public.stk_role()='admin');
create policy stk_requests_self_ins on public.stk_requests for insert to authenticated with check (user_id = auth.uid());
create policy stk_requests_self_sel on public.stk_requests for select to authenticated using (user_id = auth.uid());
