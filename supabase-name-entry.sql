begin;

-- 이름만 입력하는 공개 공동 저장소. 기존 학생/회원/수정 기록은 삭제하지 않습니다.
-- 접속 주소를 아는 누구나 학생 작성본과 수정 기록을 읽고 편집할 수 있습니다.
-- 이름과 방문자 ID는 본인 인증 정보가 아닙니다.
create or replace function km_private.public_context(visitor_name text, visitor_id uuid)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if visitor_name is null or char_length(trim(visitor_name)) not between 1 and 40
     or visitor_id is null then
    raise exception '이름을 1~40자로 입력해 주세요.';
  end if;
  perform set_config('km.public_name', trim(visitor_name), true);
  perform set_config('km.public_actor', visitor_id::text, true);
end;
$$;
revoke all on function km_private.public_context(text, uuid) from public, anon, authenticated;

create or replace function km_private.record_edit()
returns trigger language plpgsql security definer set search_path = '' as $$
declare
  editor_name text;
  actor_id uuid;
  authenticated_actor uuid;
begin
  editor_name := nullif(current_setting('km.public_name', true), '');
  if editor_name is not null then
    actor_id := nullif(current_setting('km.public_actor', true), '')::uuid;
    if actor_id is null or char_length(trim(editor_name)) not between 1 and 40 then
      raise exception '입장 이름을 확인해 주세요.';
    end if;
    -- 방문자 ID를 auth.users 외래 키에 넣지 않습니다.
    authenticated_actor := null;
  else
    authenticated_actor := auth.uid();
    actor_id := authenticated_actor;
    select m.display_name into editor_name from public.km_members m
      where m.user_id = authenticated_actor;
    if editor_name is null then
      raise exception '입장 후 편집해 주세요.';
    end if;
  end if;
  if TG_OP = 'DELETE' then
    insert into public.km_edit_history (draft_id, action, actor, actor_name, old_data)
      values (old.draft_id, TG_OP, actor_id, editor_name, old.data);
    return old;
  end if;
  if TG_OP = 'UPDATE' and new.draft_id <> old.draft_id then
    raise exception '작성본 식별자는 변경할 수 없습니다.';
  end if;
  new.edited_by := authenticated_actor;
  new.edited_name := editor_name;
  new.updated_at := now();
  new.version := case when TG_OP = 'UPDATE' then old.version + 1 else 1 end;
  insert into public.km_edit_history (draft_id, action, actor, actor_name, old_data, new_data)
    values (new.draft_id, TG_OP, actor_id, editor_name,
      case when TG_OP = 'UPDATE' then old.data else null end, new.data);
  return new;
end;
$$;
revoke all on function km_private.record_edit() from public, anon, authenticated;

create or replace function public.km_public_list(
  visitor_name text, visitor_id uuid, page_offset integer default 0, page_size integer default 500
) returns setof public.student_drafts
language plpgsql security definer set search_path = '' as $$
begin
  perform km_private.public_context(visitor_name, visitor_id);
  return query select d.* from public.student_drafts d order by d.draft_id
    limit greatest(1, least(page_size, 500)) offset greatest(page_offset, 0);
end;
$$;

create or replace function public.km_public_write(
  visitor_name text, visitor_id uuid, target_id text, draft_data jsonb default null,
  expected_version bigint default null, delete_draft boolean default false
) returns table(draft_id text, version bigint, edited_name text, edited_by uuid, updated_at timestamptz)
language plpgsql security definer set search_path = '' as $$
begin
  perform km_private.public_context(visitor_name, visitor_id);
  if target_id is null or char_length(target_id) not between 1 and 200 then
    raise exception '작성본 식별자를 확인해 주세요.';
  end if;
  if delete_draft then
    if expected_version is null then raise exception '삭제할 작성본의 버전이 필요합니다.'; end if;
    return query delete from public.student_drafts d
      where d.draft_id = target_id and d.version = expected_version
      returning d.draft_id, d.version, d.edited_name, d.edited_by, d.updated_at;
  else
    if draft_data is null or jsonb_typeof(draft_data) <> 'object' then
      raise exception '학생 작성본 내용을 확인해 주세요.';
    end if;
    if expected_version is null then
      return query insert into public.student_drafts as d (draft_id, data)
        values (target_id, draft_data)
        returning d.draft_id, d.version, d.edited_name, d.edited_by, d.updated_at;
    else
      return query update public.student_drafts d set data = draft_data
        where d.draft_id = target_id and d.version = expected_version
        returning d.draft_id, d.version, d.edited_name, d.edited_by, d.updated_at;
    end if;
  end if;
end;
$$;

create or replace function public.km_public_history(
  visitor_name text, visitor_id uuid, target_id text default null, before_id bigint default null
) returns setof public.km_edit_history
language plpgsql security definer set search_path = '' as $$
begin
  perform km_private.public_context(visitor_name, visitor_id);
  return query select h.* from public.km_edit_history h
    where (target_id is null or h.draft_id = target_id)
      and (before_id is null or h.id < before_id)
    order by h.id desc limit 10;
end;
$$;

revoke all on function public.km_public_list(text,uuid,integer,integer) from public;
revoke all on function public.km_public_write(text,uuid,text,jsonb,bigint,boolean) from public;
revoke all on function public.km_public_history(text,uuid,text,bigint) from public;
grant execute on function public.km_public_list(text,uuid,integer,integer) to anon, authenticated;
grant execute on function public.km_public_write(text,uuid,text,jsonb,bigint,boolean) to anon, authenticated;
grant execute on function public.km_public_history(text,uuid,text,bigint) to anon, authenticated;
-- 테이블 RLS 및 기존 초대 계정의 권한은 유지합니다. 공개 접근은 위 함수로 처리합니다.
notify pgrst, 'reload schema';
commit;
select '이름 입장 설정 완료' as result;
