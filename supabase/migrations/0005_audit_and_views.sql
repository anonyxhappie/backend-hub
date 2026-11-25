-- 0005_audit_and_views.sql
-- Security audit log and invoker-scoped views (never SECURITY DEFINER views).

CREATE TABLE public.audit_events (
  id bigserial PRIMARY KEY,
  app_id text REFERENCES public.apps(id) ON DELETE SET NULL,
  actor_user_id uuid,
  event_type text NOT NULL CHECK (char_length(trim(event_type)) BETWEEN 1 AND 80),
  outcome text NOT NULL CHECK (outcome IN ('allowed', 'denied', 'error')),
  detail jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(detail) = 'object'),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_events_app_created ON public.audit_events (app_id, created_at DESC);

ALTER TABLE public.audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_events FORCE ROW LEVEL SECURITY;

CREATE POLICY audit_events_select_admin
  ON public.audit_events
  FOR SELECT
  TO authenticated
  USING (
    app_id = hub_auth.current_app_id()
    AND hub_auth.is_active_app(app_id)
    AND hub_auth.has_active_membership(app_id, hub_auth.current_user_id())
    AND hub_auth.has_app_role(app_id, ARRAY['admin', 'owner'])
  );

REVOKE ALL ON public.audit_events FROM PUBLIC, anon, authenticated;
GRANT SELECT ON public.audit_events TO authenticated;
GRANT ALL ON public.audit_events TO service_role;
GRANT USAGE, SELECT ON SEQUENCE public.audit_events_id_seq TO service_role;

-- Security-invoker views: strictly honor the querying user's RLS policies.
CREATE OR REPLACE VIEW public.app_member_summary
WITH (security_invoker = true) AS
SELECT
  m.app_id,
  m.user_id,
  m.role,
  m.status,
  p.display_name,
  p.updated_at AS profile_updated_at
FROM public.app_memberships m
LEFT JOIN public.app_profiles p
  ON p.app_id = m.app_id AND p.user_id = m.user_id;

REVOKE ALL ON public.app_member_summary FROM PUBLIC, anon, authenticated;
GRANT SELECT ON public.app_member_summary TO authenticated, service_role;

CREATE OR REPLACE VIEW public.hub_record_stats
WITH (security_invoker = true) AS
SELECT
  app_id,
  collection,
  visibility,
  count(*)::integer AS total_records
FROM public.app_records
GROUP BY app_id, collection, visibility;

REVOKE ALL ON public.hub_record_stats FROM PUBLIC, anon, authenticated;
GRANT SELECT ON public.hub_record_stats TO anon, authenticated, service_role;
