-- +goose Up

-- Обратимый offboarding с окном хранения.
--
-- Раньше offboard был необратим в момент нажатия: доступы отзывались,
-- managed-аккаунты удалялись в целевых системах, общие секреты уничтожались
-- в Vault, а принципал становился tombstone status='deleted'. Промах по
-- строке стоил ровно столько же, сколько осознанное решение, а возврат
-- человека требовал четырёх ручных admin-вызовов и заводил НОВОГО принципала
-- с новым id — история доступов не восстанавливалась.
--
-- Новый статус pending_purge разделяет два разных события: «доступ закрыт
-- сейчас» и «данные уничтожены навсегда». В pending_purge доступ уже
-- заблокирован (обратимым каскадом disable, Vault и bindings целы), а
-- реальное уничтожение выполняет фоновая задача по истечении purge_after.
-- До этого момента принципал возвращается одной операцией.
alter table principals drop constraint principals_status_check;
alter table principals add constraint principals_status_check
    check (status in ('active', 'disabled', 'pending_purge', 'deleted'));

-- Момент, начиная с которого принципал подлежит необратимому уничтожению.
-- NULL — принципал не выводится из системы; заполняется при переходе в
-- pending_purge и очищается при восстановлении.
alter table principals add column purge_after timestamptz;

-- Выборка кандидатов на уничтожение — предикат фоновой задачи обслуживания.
create index principals_purge_after_idx
    on principals (purge_after)
    where purge_after is not null;

-- +goose Down

drop index principals_purge_after_idx;
alter table principals drop column purge_after;

-- Откат возможен, только пока принципалов в pending_purge нет: такие строки
-- нарушат восстановленное ограничение.
alter table principals drop constraint principals_status_check;
alter table principals add constraint principals_status_check
    check (status in ('active', 'disabled', 'deleted'));
