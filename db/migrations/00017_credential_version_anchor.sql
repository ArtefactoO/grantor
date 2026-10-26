-- +goose Up
-- Якорь версии credential: обнаружение правок пароля мимо grantor.
--
-- Проблема: grantor вызывает ProveCredential только сразу после ротации и в
-- connector-restore, фоновой сверки нет. Если пароль поменяли руками в Vault
-- (или на самом таргете), «Получить учётные данные» отдаёт пароль, который в
-- целевой системе не работает, и ничто об этом не сообщает: дрифт считает
-- bindings и объекты, а не валидность пароля. Само чинится только следующей
-- ротацией.
--
-- Решение — дешёвый детектор без обращения к целевой системе. Vault KV v2
-- нумерует версии секрета, и номер уже возвращается на каждой записи.
-- Запоминаем версию, которую grantor реально применил к таргету, и
-- периодически сверяем её с текущей версией в Vault. Расхождение означает,
-- что секрет переписали в обход grantor.
--
-- Почему два столбца, а не флаг: флаг пришлось бы кем-то сбрасывать и он не
-- отвечает на вопрос «насколько разошлись». Пара версий самодостаточна,
-- проверяется глазами в psql, а сам finding остаётся чистым SQL-выражением
-- без отдельной машины состояний.

alter table accounts
    -- Версия секрета, применённая к целевой системе. 0 — якоря нет:
    -- исторические аккаунты до этой миграции и аккаунты, чей пароль grantor
    -- никогда не применял (adopt mode=metadata). Такие из сверки исключены:
    -- сравнивать не с чем, а ложный finding хуже отсутствующего.
    add column credential_version integer not null default 0
        check (credential_version >= 0),
    -- Версия, которую последняя сверка увидела в Vault. 0 — не сверялось.
    add column credential_observed_version integer not null default 0
        check (credential_observed_version >= 0),
    -- Когда сверка выполнялась последний раз. NULL — ни разу.
    add column credential_checked_at timestamptz;

comment on column accounts.credential_version is
    'Vault KV version applied to the target; 0 means no anchor to compare against';
comment on column accounts.credential_observed_version is
    'Vault KV version seen by the last credential check; 0 means never checked';
comment on column accounts.credential_checked_at is
    'When the credential version was last compared against Vault';

-- Частичный индекс под выборку сверки: интересны только управляемые живые
-- аккаунты с якорем и путём в Vault. Их существенно меньше, чем строк в
-- таблице, поэтому полный индекс был бы напрасным.
create index accounts_credential_anchor_idx
    on accounts (connection_id)
    where ownership = 'managed'
      and status <> 'deleted'
      and credential_version > 0
      and vault_path <> '';

-- +goose Down
drop index if exists accounts_credential_anchor_idx;
alter table accounts
    drop column if exists credential_checked_at,
    drop column if exists credential_observed_version,
    drop column if exists credential_version;
