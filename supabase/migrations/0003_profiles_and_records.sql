-- 0003_profiles_and_records.sql
-- App-scoped user profiles and records with strict tenant/owner immutability,
-- RLS policies (USING + WITH CHECK), column grants, and atomic record quota enforcement.

CREATE TABLE public.app_profiles (
  app_id text NOT NULL,
  user_id uuid NOT NULL,
  display_name text NOT NULL CHECK (char_length(trim(display_name)) BETWEEN 1 AND 80),
  bio text NOT NULL DEFAULT '' CHECK (char_length(bio) <= 500),
  avatar_path text CHECK (avatar_path IS NULL OR char_length(avatar_path) <= 255),
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(metadata) = 'object'),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (app_id, user_id),
  FOREIGN KEY (app_id, user_id) REFERENCES public.app_memberships(app_id, user_id) ON DELETE CASCADE
);

CREATE TRIGGER trg_app_profiles_updated_at
  BEFORE UPDATE ON public.app_profiles
  FOR EACH ROW
  EXECUTE FUNCTION hub_auth.touch_updated_at();

CREATE OR REPLACE FUNCTION hub_auth.guard_profile_immutable_fields()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
BEGIN
  IF NEW.app_id IS DISTINCT FROM OLD.app_id
    OR NEW.user_id IS DISTINCT FROM OLD.user_id
    OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'IMMUTABLE_FIELD: app_id, user_id, and created_at cannot be modified'
      USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_app_profiles_immutable
  BEFORE UPDATE ON public.app_profiles
  FOR EACH ROW
  EXECUTE FUNCTION hub_auth.guard_profile_immutable_fields();

ALTER TABLE public.app_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.app_profiles FORCE ROW LEVEL SECURITY;

CREATE POLICY profiles_select_scoped
  ON public.app_profiles
  FOR SELECT
  TO authenticated
  USING (
    app_id = hub_auth.current_app_id()
    AND hub_auth.is_active_app(app_id)
    AND hub_auth.has_active_membership(app_id, hub_auth.current_user_id())
    AND hub_auth.has_capability('profile:read')
    AND (
      user_id = hub_auth.current_user_id()
      OR hub_auth.has_app_role(app_id, ARRAY['admin', 'owner'])
    )
  );

CREATE POLICY profiles_insert_own
  ON public.app_profiles
  FOR INSERT
  TO authenticated
  WITH CHECK (
    app_id = hub_auth.current_app_id()
    AND user_id = hub_auth.current_user_id()
    AND hub_auth.is_active_app(app_id)
    AND hub_auth.has_active_membership(app_id, hub_auth.current_user_id())
    AND hub_auth.has_capability('profile:write')
  );

CREATE POLICY profiles_update_own
  ON public.app_profiles
  FOR UPDATE
  TO authenticated
  USING (
    app_id = hub_auth.current_app_id()
    AND user_id = hub_auth.current_user_id()
    AND hub_auth.is_active_app(app_id)
    AND hub_auth.has_active_membership(app_id, hub_auth.current_user_id())
    AND hub_auth.has_capability('profile:write')
  )
  WITH CHECK (
    app_id = hub_auth.current_app_id()
    AND user_id = hub_auth.current_user_id()
    AND hub_auth.is_active_app(app_id)
    AND hub_auth.has_active_membership(app_id, hub_auth.current_user_id())
    AND hub_auth.has_capability('profile:write')
  );

CREATE POLICY profiles_delete_own
  ON public.app_profiles
  FOR DELETE
  TO authenticated
  USING (
    app_id = hub_auth.current_app_id()
    AND user_id = hub_auth.current_user_id()
    AND hub_auth.is_active_app(app_id)
    AND hub_auth.has_active_membership(app_id, hub_auth.current_user_id())
    AND hub_auth.has_capability('profile:write')
  );

REVOKE ALL ON public.app_profiles FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, DELETE ON public.app_profiles TO authenticated;
GRANT UPDATE (display_name, bio, avatar_path, metadata) ON public.app_profiles TO authenticated;
GRANT ALL ON public.app_profiles TO service_role;

-- App-scoped records
CREATE TABLE public.app_records (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  app_id text NOT NULL REFERENCES public.apps(id) ON DELETE RESTRICT,
  owner_id uuid NOT NULL,
  collection text NOT NULL CHECK (collection ~ '^[a-z0-9][a-z0-9_-]{0,47}$'),
  visibility text NOT NULL DEFAULT 'private' CHECK (visibility IN ('private', 'app', 'public')),
  title text NOT NULL CHECK (char_length(trim(title)) BETWEEN 1 AND 200),
  payload jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(payload) = 'object'),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (app_id, owner_id) REFERENCES public.app_memberships(app_id, user_id) ON DELETE RESTRICT
);

CREATE INDEX idx_app_records_app_collection_created
  ON public.app_records (app_id, collection, created_at DESC);
CREATE INDEX idx_app_records_app_owner
  ON public.app_records (app_id, owner_id);

CREATE TRIGGER trg_app_records_updated_at
  BEFORE UPDATE ON public.app_records
  FOR EACH ROW
  EXECUTE FUNCTION hub_auth.touch_updated_at();

-- Validates allowed collection, enforces immutable id/app_id/owner_id/created_at,
-- and enforces atomic per-app and per-user record quotas using advisory locks.
CREATE OR REPLACE FUNCTION hub_auth.enforce_record_invariants()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_app public.apps;
  v_app_count integer;
  v_user_count integer;
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF NEW.id IS DISTINCT FROM OLD.id
      OR NEW.app_id IS DISTINCT FROM OLD.app_id
      OR NEW.owner_id IS DISTINCT FROM OLD.owner_id
      OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
      RAISE EXCEPTION 'IMMUTABLE_FIELD: id, app_id, owner_id, and created_at cannot be modified'
        USING ERRCODE = '42501';
    END IF;
  END IF;

  SELECT * INTO v_app FROM public.apps WHERE id = NEW.app_id;
  IF NOT FOUND OR v_app.status <> 'active' THEN
    RAISE EXCEPTION 'APP_INACTIVE: app does not exist or is not active'
      USING ERRCODE = '42501';
  END IF;

  IF NOT (NEW.collection = ANY(v_app.allowed_collections)) THEN
    RAISE EXCEPTION 'INVALID_COLLECTION: collection "%" is not allowed for app "%"', NEW.collection, NEW.app_id
      USING ERRCODE = '22023';
  END IF;

  IF TG_OP = 'INSERT' THEN
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('rec_app:' || NEW.app_id));
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('rec_user:' || NEW.app_id || ':' || NEW.owner_id::text));

    SELECT count(*)::integer INTO v_app_count
    FROM public.app_records
    WHERE app_id = NEW.app_id;

    IF v_app_count >= v_app.max_records_per_app THEN
      RAISE EXCEPTION 'QUOTA_EXCEEDED: app record quota reached (% / %)', v_app_count, v_app.max_records_per_app
        USING ERRCODE = 'P0001';
    END IF;

    SELECT count(*)::integer INTO v_user_count
    FROM public.app_records
    WHERE app_id = NEW.app_id AND owner_id = NEW.owner_id;

    IF v_user_count >= v_app.max_records_per_user THEN
      RAISE EXCEPTION 'QUOTA_EXCEEDED: per-user record quota reached (% / %)', v_user_count, v_app.max_records_per_user
        USING ERRCODE = 'P0001';
    END IF;
  END IF;

  RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION hub_auth.enforce_record_invariants() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION hub_auth.enforce_record_invariants() TO authenticated, service_role;

CREATE TRIGGER trg_app_records_invariants
  BEFORE INSERT OR UPDATE ON public.app_records
  FOR EACH ROW
  EXECUTE FUNCTION hub_auth.enforce_record_invariants();

ALTER TABLE public.app_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.app_records FORCE ROW LEVEL SECURITY;

-- Public reads are strictly scoped to the verified active app AND require allow_public_read = true.
CREATE POLICY records_select_scoped
  ON public.app_records
  FOR SELECT
  TO anon, authenticated
  USING (
    app_id = hub_auth.current_app_id()
    AND hub_auth.is_active_app(app_id)
    AND collection = ANY(hub_auth.app_allowed_collections(app_id))
    AND (
      (
        visibility = 'public'
        AND hub_auth.app_allows_public_read(app_id)
        AND (
          hub_auth.has_capability('records:read_public')
          OR hub_auth.has_capability('records:read')
        )
      )
      OR (
        hub_auth.current_user_id() IS NOT NULL
        AND hub_auth.has_active_membership(app_id, hub_auth.current_user_id())
        AND hub_auth.has_capability('records:read')
        AND (
          owner_id = hub_auth.current_user_id()
          OR visibility = 'app'
          OR hub_auth.has_app_role(app_id, ARRAY['admin', 'owner'])
        )
      )
    )
  );

CREATE POLICY records_insert_scoped
  ON public.app_records
  FOR INSERT
  TO authenticated
  WITH CHECK (
    app_id = hub_auth.current_app_id()
    AND owner_id = hub_auth.current_user_id()
    AND hub_auth.is_active_app(app_id)
    AND hub_auth.has_active_membership(app_id, hub_auth.current_user_id())
    AND hub_auth.has_capability('records:write')
    AND collection = ANY(hub_auth.app_allowed_collections(app_id))
  );

CREATE POLICY records_update_scoped
  ON public.app_records
  FOR UPDATE
  TO authenticated
  USING (
    app_id = hub_auth.current_app_id()
    AND hub_auth.is_active_app(app_id)
    AND hub_auth.has_active_membership(app_id, hub_auth.current_user_id())
    AND hub_auth.has_capability('records:write')
    AND (
      owner_id = hub_auth.current_user_id()
      OR hub_auth.has_app_role(app_id, ARRAY['admin', 'owner'])
    )
  )
  WITH CHECK (
    app_id = hub_auth.current_app_id()
    AND hub_auth.is_active_app(app_id)
    AND hub_auth.has_active_membership(app_id, hub_auth.current_user_id())
    AND hub_auth.has_capability('records:write')
    AND collection = ANY(hub_auth.app_allowed_collections(app_id))
    AND (
      owner_id = hub_auth.current_user_id()
      OR hub_auth.has_app_role(app_id, ARRAY['admin', 'owner'])
    )
  );

CREATE POLICY records_delete_scoped
  ON public.app_records
  FOR DELETE
  TO authenticated
  USING (
    app_id = hub_auth.current_app_id()
    AND hub_auth.is_active_app(app_id)
    AND hub_auth.has_active_membership(app_id, hub_auth.current_user_id())
    AND hub_auth.has_capability('records:delete')
    AND (
      owner_id = hub_auth.current_user_id()
      OR hub_auth.has_app_role(app_id, ARRAY['admin', 'owner'])
    )
  );

REVOKE ALL ON public.app_records FROM PUBLIC, anon, authenticated;
GRANT SELECT ON public.app_records TO anon;
GRANT SELECT, INSERT, DELETE ON public.app_records TO authenticated;
GRANT UPDATE (collection, visibility, title, payload) ON public.app_records TO authenticated;
GRANT ALL ON public.app_records TO service_role;
