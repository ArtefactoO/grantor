-- +goose Up
ALTER TABLE service_tokens ADD COLUMN permissions text[] NOT NULL DEFAULT '{}';
ALTER TABLE service_tokens ADD CONSTRAINT service_tokens_permissions_known
  CHECK (permissions <@ ARRAY['connections:create']::text[]);

-- +goose Down
ALTER TABLE service_tokens DROP CONSTRAINT service_tokens_permissions_known;
ALTER TABLE service_tokens DROP COLUMN permissions;
