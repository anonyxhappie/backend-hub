-- Non-production local development seed ONLY.
-- Never run against staging or production.
-- Registers two demo portfolio apps (`notes-demo` and `habits-demo`) and private buckets.

INSERT INTO public.apps (
  id, name, status, allowed_origins, allowed_collections,
  allow_self_enroll, allow_public_read,
  max_records_per_app, max_records_per_user,
  max_storage_bytes, max_user_storage_bytes, max_upload_bytes,
  allowed_mime_types, rate_limit_rpm
)
VALUES
  (
    'notes-demo',
    'Notes Demo App',
    'active',
    ARRAY['http://127.0.0.1:4100', 'http://localhost:4100'],
    ARRAY['notes', 'snippets'],
    true,
    true,
    1000,
    100,
    20971520,
    5242880,
    1048576,
    ARRAY['text/plain', 'text/markdown', 'application/json', 'image/png', 'image/jpeg', 'application/pdf'],
    120
  ),
  (
    'habits-demo',
    'Habits Tracker App',
    'active',
    ARRAY['http://127.0.0.1:4101', 'http://localhost:4101'],
    ARRAY['habits', 'checkins'],
    false,
    false,
    1000,
    100,
    20971520,
    5242880,
    1048576,
    ARRAY['application/json', 'text/plain'],
    120
  )
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.storage_buckets (id, app_id, is_public)
VALUES
  ('notes-files', 'notes-demo', false),
  ('habits-files', 'habits-demo', false)
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.app_usage (app_id)
VALUES ('notes-demo'), ('habits-demo')
ON CONFLICT (app_id) DO NOTHING;
