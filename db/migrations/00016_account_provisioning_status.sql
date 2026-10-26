-- +goose Up

-- Две новые точки жизненного цикла учётной записи, разделяющие «строка в
-- metadata есть» и «учётка реально существует в целевой системе»:
--
--   provisioning — строка создана control plane как резервация identity, но
--     account.create ещё не подтвердил учётку на target. До успеха такая
--     запись не является живым managed-аккаунтом: она не участвует в
--     ротации и прочих массовых операциях принципала и не выдаёт ложную
--     уверенность, что доступ выдан. Провалившийся account.create ОСТАВЛЯЕТ
--     аккаунт в этом статусе — так retry и повторный запрос доступа
--     переиспользуют ту же строку вместо создания дубля.
--
--   missing — discovery не нашёл managed-аккаунт в целевой системе.
--     Симметрично resources.status='missing': discovery ничего не удаляет,
--     а фиксирует расхождение, которое попадает в отчёт дрифта.
--
-- Существующие строки не меняются: оба значения появляются только у новых
-- переходов.
alter table accounts drop constraint accounts_status_check;
alter table accounts add constraint accounts_status_check
    check (status in ('active', 'disabled', 'deleted', 'provisioning', 'missing'));

-- +goose Down

-- Откат возможен только пока строк в новых статусах нет: они нарушат
-- восстановленное ограничение.
alter table accounts drop constraint accounts_status_check;
alter table accounts add constraint accounts_status_check
    check (status in ('active', 'disabled', 'deleted'));
