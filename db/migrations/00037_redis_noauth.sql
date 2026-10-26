-- +goose Up
alter table connections add column auth_mode text not null default 'password';
alter table connections add constraint connections_auth_mode_check check
 (auth_mode = 'password' or (auth_mode = 'none' and engine = 'redis' and vault_admin_path = ''));

alter table connection_admin_credential_changes drop constraint connection_admin_credential_changes_candidate_mode_check;
alter table connection_admin_credential_changes add constraint connection_admin_credential_changes_candidate_mode_check
 check (candidate_mode in ('provided', 'generated', 'none'));
alter table connection_admin_credential_changes drop constraint connection_admin_credential_changes_stage_vault_path_check;
alter table connection_admin_credential_changes add constraint connection_admin_credential_changes_stage_vault_path_check
 check ((candidate_mode = 'none' and mode = 'switch' and stage_vault_path = '' and not stage_cleanup_pending) or
        (candidate_mode <> 'none' and stage_vault_path <> ''));
alter table connection_admin_credential_changes drop constraint connection_admin_credential_changes_staged_vault_version_check;
alter table connection_admin_credential_changes add constraint connection_admin_credential_changes_staged_vault_version_check
 check (staged_vault_version is null or (candidate_mode <> 'none' and staged_vault_version > 0) or (candidate_mode = 'none' and staged_vault_version = 0));
alter table connection_admin_credential_changes drop constraint connection_admin_credential_chang_canonical_vault_version_check;
alter table connection_admin_credential_changes add constraint connection_admin_credential_chang_canonical_vault_version_check
 check ((candidate_mode <> 'none' and canonical_vault_version > 0) or (candidate_mode = 'none' and canonical_vault_version = 0));

alter table connection_registrations alter column credential_source_id drop not null;
alter table connection_registrations drop constraint connection_registrations_credential_source_version_check;
alter table connection_registrations add constraint connection_registrations_credential_source_version_check
 check ((credential_source_id is not null and credential_source_version > 0) or
        (credential_source_id is null and credential_source_version = 0 and spec->>'engine' = 'redis' and spec->>'auth_mode' = 'none'));
alter table connection_registrations drop constraint connection_registrations_check;
alter table connection_registrations add constraint connection_registrations_check check
 ((phase = 'preparing' and canonical_version = 0) or
  (phase in ('credential_ready', 'registered') and
    (canonical_version > 0 or (credential_source_id is null and spec->>'auth_mode' = 'none'))) or
  phase in ('canceling', 'cancelled'));

-- +goose Down
-- Old binaries cannot represent an unauthenticated inventory connection or
-- its durable receipts. Refuse rollback while any such history remains.
-- +goose StatementBegin
do $$ begin
 if exists(select 1 from connections where auth_mode = 'none') or
    exists(select 1 from connection_admin_credential_changes where candidate_mode = 'none') or
    exists(select 1 from connection_registrations where credential_source_id is null) then
  raise exception 'cannot roll back Redis no-auth while connections or receipts remain';
 end if;
end $$;
-- +goose StatementEnd
alter table connection_registrations drop constraint connection_registrations_check;
alter table connection_registrations add constraint connection_registrations_check check
 ((phase = 'preparing' and canonical_version = 0) or
  (phase in ('credential_ready', 'registered') and canonical_version > 0) or phase in ('canceling', 'cancelled'));
alter table connection_registrations drop constraint connection_registrations_credential_source_version_check;
alter table connection_registrations add constraint connection_registrations_credential_source_version_check check (credential_source_version > 0);
alter table connection_registrations alter column credential_source_id set not null;
alter table connection_admin_credential_changes drop constraint connection_admin_credential_chang_canonical_vault_version_check;
alter table connection_admin_credential_changes add constraint connection_admin_credential_chang_canonical_vault_version_check check (canonical_vault_version > 0);
alter table connection_admin_credential_changes drop constraint connection_admin_credential_changes_staged_vault_version_check;
alter table connection_admin_credential_changes add constraint connection_admin_credential_changes_staged_vault_version_check check (staged_vault_version is null or staged_vault_version > 0);
alter table connection_admin_credential_changes drop constraint connection_admin_credential_changes_stage_vault_path_check;
alter table connection_admin_credential_changes add constraint connection_admin_credential_changes_stage_vault_path_check check (stage_vault_path <> '');
alter table connection_admin_credential_changes drop constraint connection_admin_credential_changes_candidate_mode_check;
alter table connection_admin_credential_changes add constraint connection_admin_credential_changes_candidate_mode_check check (candidate_mode in ('provided','generated'));
alter table connections drop column auth_mode;
