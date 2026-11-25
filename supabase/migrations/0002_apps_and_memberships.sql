-- 0002_apps_and_memberships.sql
-- App registry, per-app memberships, status/role immutability, and authorization helper functions.

CREATE TABLE public.apps (
  id text PRIMARY KEY CHECK (id ~ '^[a-z0-9][a-z0-9-]{1,48}[a-z0-9]$'),
  name text NOT NULL CHECK (char_length(trim(name)) BETWEEN 1 AND 120),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'archived')),
  allowed_origins text[] NOT NULL DEFAULT ARRAY[]::text[],
  allowed_collections text[] NOT NULL DEFAULT ARRAY['notes']::text[],
  allow_self_enroll boolean NOT NULL DEFAULT false,
  allow_public_read boolean NOT NULL DEFAULT false,
  max_records_per_app integer NOT NULL DEFAULT 5000 CHECK (max_records_per_app >= 0),
  max_records_per_user integer NOT NULL DEFAULT 500 CHECK (max_records_per_user >= 0),
  max_storage_bytes bigint NOT NULL DEFAULT 52428800 CHECK (max_storage_bytes >= 0),
  max_user_storage_bytes bigint NOT NULL DEFAULT 10485760 CHECK (max_user_storage_bytes >= 0),
  max_upload_bytes bigint NOT NULL DEFAULT 2097152 CHECK (max_upload_bytes > 0),
  allowed_mime_types text[] NOT NULL DEFAULT ARRAY[
    'text/plain',
    'text/markdown',
    'application/json',
    'image/png',
    'image/jpeg',
    'application/pdf'
  ]::text[],
  rate_limit_rpm integer NOT NULL DEFAULT 120 CHECK (rate_limit_rpm > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TRIGGER trg_apps_updated_at
  BEFORE UPDATE ON public.apps
  FOR EACH ROW
  EXECUTE FUNCTION hub_auth.touch_updated_at();

CREATE TABLE public.app_memberships (
  app_id text NOT NULL REFERENCES public.apps(id) ON DELETE RESTRICT,
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  role text NOT NULL DEFAULT 'member' CHECK (role IN ('viewer', 'member', 'admin', 'owner')),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'revoked')),
  capabilities text[] NOT NULL DEFAULT ARRAY[
    'profile:read',
    'profile:write',
    'records:read',
    'records:write',
    'records:delete',
    'storage:read',
    'storage:write',
    'storage:delete'
  ]::text[],
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (app_id, user_id)
);

CREATE INDEX idx_app_memberships_user_id ON public.app_memberships (user_id);

CREATE TRIGGER trg_app_memberships_updated_at
  BEFORE UPDATE ON public.app_memberships
  FOR EACH ROW
  EXECUTE FUNCTION hub_auth.touch_updated_at();

-- Prevent ordinary clients from mutating membership identity/role/status even if granted in future.
CREATE OR REPLACE FUNCTION hub_auth.guard_membership_mutation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, hub_auth
AS $$
BEGIN
  IF current_user <> 'service_role' AND NOT pg_has_role(current_user, 'service_role', 'MEMBER') THEN
    IF NEW.app_id IS DISTINCT FROM OLD.app_id
      OR NEW.user_id IS DISTINCT FROM OLD.user_id
      OR NEW.role IS DISTINCT FROM OLD.role
      OR NEW.status IS DISTINCT FROM OLD.status
      OR NEW.capabilities IS DISTINCT FROM OLD.capabilities THEN
      RAISE EXCEPTION 'IMMUTABLE_MEMBERSHIP_FIELDS: ordinary clients cannot alter membership role, status, or tenant fields'
        USING ERRCODE = '42501';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_app_memberships_immutable
  BEFORE UPDATE ON public.app_memberships
  FOR EACH ROW
  EXECUTE FUNCTION hub_auth.guard_membership_mutation();

-- Helper functions evaluated by RLS with fixed safe search_path.
CREATE OR REPLACE FUNCTION hub_auth.is_active_app(p_app_id text)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.apps a
    WHERE a.id = p_app_id
      AND a.status = 'active'
  );
$$;

CREATE OR REPLACE FUNCTION hub_auth.app_allowed_collections(p_app_id text)
RETURNS text[]
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT COALESCE(
    (SELECT a.allowed_collections FROM public.apps a WHERE a.id = p_app_id AND a.status = 'active'),
    ARRAY[]::text[]
  );
$$;

CREATE OR REPLACE FUNCTION hub_auth.app_allows_public_read(p_app_id text)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.apps a
    WHERE a.id = p_app_id
      AND a.status = 'active'
      AND a.allow_public_read = true
  );
$$;

CREATE OR REPLACE FUNCTION hub_auth.has_active_membership(p_app_id text, p_user_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.app_memberships m
    JOIN public.apps a ON a.id = m.app_id
    WHERE m.app_id = p_app_id
      AND m.user_id = p_user_id
      AND m.status = 'active'
      AND a.status = 'active'
  );
$$;

CREATE OR REPLACE FUNCTION hub_auth.has_app_role(p_app_id text, p_roles text[])
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, hub_auth
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.app_memberships m
    JOIN public.apps a ON a.id = m.app_id
    WHERE m.app_id = p_app_id
      AND m.user_id = hub_auth.current_user_id()
      AND m.status = 'active'
      AND a.status = 'active'
      AND m.role = ANY(p_roles)
  );
$$;

REVOKE ALL ON FUNCTION hub_auth.is_active_app(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION hub_auth.app_allowed_collections(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION hub_auth.app_allows_public_read(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION hub_auth.has_active_membership(text, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION hub_auth.has_app_role(text, text[]) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION hub_auth.is_active_app(text) TO anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION hub_auth.app_allowed_collections(text) TO anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION hub_auth.app_allows_public_read(text) TO anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION hub_auth.has_active_membership(text, uuid) TO anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION hub_auth.has_app_role(text, text[]) TO anon, authenticated, service_role;

-- Controlled self-enrollment RPC: only works for apps with allow_self_enroll = true,
-- always assigns role = 'member', and never reactivates suspended/revoked memberships.
CREATE OR REPLACE FUNCTION public.hub_self_enroll(p_app_id text)
RETURNS public.app_memberships
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, hub_auth
AS $$
DECLARE
  v_user_id uuid;
  v_app public.apps;
  v_membership public.app_memberships;
BEGIN
  v_user_id := hub_auth.current_user_id();
  IF v_user_id IS NULL THEN
    RAISE EXCEPTION 'AUTH_REQUIRED: authentication required for enrollment'
      USING ERRCODE = '42501';
  END IF;

  SELECT * INTO v_app FROM public.apps WHERE id = p_app_id;
  IF NOT FOUND OR v_app.status <> 'active' THEN
    RAISE EXCEPTION 'APP_UNAVAILABLE: target app is missing or inactive'
      USING ERRCODE = '42501';
  END IF;

  IF NOT v_app.allow_self_enroll THEN
    RAISE EXCEPTION 'ENROLLMENT_FORBIDDEN: self-enrollment is disabled for this app'
      USING ERRCODE = '42501';
  END IF;

  INSERT INTO public.app_memberships (app_id, user_id, role, status)
  VALUES (p_app_id, v_user_id, 'member', 'active')
  ON CONFLICT (app_id, user_id) DO NOTHING;

  SELECT * INTO v_membership
  FROM public.app_memberships
  WHERE app_id = p_app_id AND user_id = v_user_id;

  IF v_membership.status <> 'active' THEN
    RAISE EXCEPTION 'MEMBERSHIP_SUSPENDED: membership is not active'
      USING ERRCODE = '42501';
  END IF;

  RETURN v_membership;
END;
$$;

REVOKE ALL ON FUNCTION public.hub_self_enroll(text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.hub_self_enroll(text) TO authenticated, service_role;

-- RLS policies
ALTER TABLE public.apps ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.apps FORCE ROW LEVEL SECURITY;

ALTER TABLE public.app_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.app_memberships FORCE ROW LEVEL SECURITY;

CREATE POLICY apps_select_scoped
  ON public.apps
  FOR SELECT
  TO anon, authenticated
  USING (
    status = 'active'
    AND id = hub_auth.current_app_id()
  );

CREATE POLICY memberships_select_scoped
  ON public.app_memberships
  FOR SELECT
  TO authenticated
  USING (
    app_id = hub_auth.current_app_id()
    AND hub_auth.is_active_app(app_id)
    AND (
      (user_id = hub_auth.current_user_id() AND status = 'active')
      OR (
        hub_auth.has_active_membership(app_id, hub_auth.current_user_id())
        AND hub_auth.has_app_role(app_id, ARRAY['admin', 'owner'])
      )
    )
  );

-- Explicit least-privilege grants
REVOKE ALL ON public.apps FROM PUBLIC, anon, authenticated;
REVOKE ALL ON public.app_memberships FROM PUBLIC, anon, authenticated;

GRANT SELECT ON public.apps TO anon, authenticated;
GRANT SELECT ON public.app_memberships TO authenticated;
GRANT ALL ON public.apps, public.app_memberships TO service_role;
