-- 0004_storage_and_quotas.sql
-- Private-by-default storage buckets, path-validated storage objects,
-- atomic quota reservations, and server-side usage reconciliation.

CREATE TABLE public.storage_buckets (
  id text PRIMARY KEY CHECK (id ~ '^[a-z0-9][a-z0-9_-]{1,62}[a-z0-9]$'),
  app_id text NOT NULL REFERENCES public.apps(id) ON DELETE RESTRICT,
  is_public boolean NOT NULL DEFAULT false CHECK (is_public = false),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE public.quota_reservations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  app_id text NOT NULL REFERENCES public.apps(id) ON DELETE RESTRICT,
  user_id uuid NOT NULL,
  bytes_reserved bigint NOT NULL CHECK (bytes_reserved > 0),
  idempotency_key text,
  status text NOT NULL DEFAULT 'reserved' CHECK (status IN ('reserved', 'committed', 'released', 'expired')),
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (app_id, user_id) REFERENCES public.app_memberships(app_id, user_id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX idx_quota_reservations_idempotency
  ON public.quota_reservations (app_id, user_id, idempotency_key)
  WHERE idempotency_key IS NOT NULL;

CREATE INDEX idx_quota_reservations_active
  ON public.quota_reservations (app_id, user_id, status, expires_at);

CREATE TRIGGER trg_quota_reservations_updated_at
  BEFORE UPDATE ON public.quota_reservations
  FOR EACH ROW
  EXECUTE FUNCTION hub_auth.touch_updated_at();

CREATE TABLE public.storage_objects (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  bucket_id text NOT NULL REFERENCES public.storage_buckets(id) ON DELETE RESTRICT,
  app_id text NOT NULL REFERENCES public.apps(id) ON DELETE RESTRICT,
  owner_id uuid NOT NULL,
  relative_path text NOT NULL,
  object_path text NOT NULL,
  mime_type text NOT NULL CHECK (char_length(trim(mime_type)) BETWEEN 3 AND 127),
  size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
  sha256 text,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'deleted')),
  reservation_id uuid REFERENCES public.quota_reservations(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (bucket_id, object_path),
  FOREIGN KEY (app_id, owner_id) REFERENCES public.app_memberships(app_id, user_id) ON DELETE RESTRICT,
  CHECK (object_path = app_id || '/' || owner_id::text || '/' || relative_path),
  CHECK (relative_path ~ '^[a-zA-Z0-9._/-]{1,200}$'),
  CHECK (relative_path !~ '^/'),
  CHECK (relative_path !~ '/$'),
  CHECK (relative_path !~ '//'),
  CHECK (relative_path !~ '(^|/)\.\.?(/|$)'),
  CHECK (relative_path !~ '\\')
);

CREATE INDEX idx_storage_objects_app_owner_status
  ON public.storage_objects (app_id, owner_id, status);

CREATE TRIGGER trg_storage_objects_updated_at
  BEFORE UPDATE ON public.storage_objects
  FOR EACH ROW
  EXECUTE FUNCTION hub_auth.touch_updated_at();

-- Prevent moving objects across tenants, owners, buckets, or paths after creation.
CREATE OR REPLACE FUNCTION hub_auth.guard_storage_object_immutability()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
    OR NEW.bucket_id IS DISTINCT FROM OLD.bucket_id
    OR NEW.app_id IS DISTINCT FROM OLD.app_id
    OR NEW.owner_id IS DISTINCT FROM OLD.owner_id
    OR NEW.relative_path IS DISTINCT FROM OLD.relative_path
    OR NEW.object_path IS DISTINCT FROM OLD.object_path
    OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'IMMUTABLE_STORAGE_PATH: storage object tenant, owner, bucket, and path are immutable'
      USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_storage_objects_immutable
  BEFORE UPDATE ON public.storage_objects
  FOR EACH ROW
  EXECUTE FUNCTION hub_auth.guard_storage_object_immutability();

CREATE TABLE public.app_usage (
  app_id text PRIMARY KEY REFERENCES public.apps(id) ON DELETE CASCADE,
  active_storage_bytes bigint NOT NULL DEFAULT 0 CHECK (active_storage_bytes >= 0),
  reserved_storage_bytes bigint NOT NULL DEFAULT 0 CHECK (reserved_storage_bytes >= 0),
  active_object_count integer NOT NULL DEFAULT 0 CHECK (active_object_count >= 0),
  record_count integer NOT NULL DEFAULT 0 CHECK (record_count >= 0),
  last_reconciled_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TRIGGER trg_app_usage_updated_at
  BEFORE UPDATE ON public.app_usage
  FOR EACH ROW
  EXECUTE FUNCTION hub_auth.touch_updated_at();

-- RLS on storage & quota tables
ALTER TABLE public.storage_buckets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.storage_buckets FORCE ROW LEVEL SECURITY;

ALTER TABLE public.quota_reservations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.quota_reservations FORCE ROW LEVEL SECURITY;

ALTER TABLE public.storage_objects ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.storage_objects FORCE ROW LEVEL SECURITY;

ALTER TABLE public.app_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.app_usage FORCE ROW LEVEL SECURITY;

CREATE POLICY buckets_select_scoped
  ON public.storage_buckets
  FOR SELECT
  TO authenticated
  USING (
    app_id = hub_auth.current_app_id()
    AND hub_auth.is_active_app(app_id)
    AND hub_auth.has_active_membership(app_id, hub_auth.current_user_id())
  );

CREATE POLICY reservations_select_own
  ON public.quota_reservations
  FOR SELECT
  TO authenticated
  USING (
    app_id = hub_auth.current_app_id()
    AND user_id = hub_auth.current_user_id()
    AND hub_auth.is_active_app(app_id)
    AND hub_auth.has_active_membership(app_id, hub_auth.current_user_id())
  );

CREATE POLICY storage_objects_select_scoped
  ON public.storage_objects
  FOR SELECT
  TO authenticated
  USING (
    app_id = hub_auth.current_app_id()
    AND hub_auth.is_active_app(app_id)
    AND hub_auth.has_active_membership(app_id, hub_auth.current_user_id())
    AND hub_auth.has_capability('storage:read')
    AND status = 'active'
    AND (
      owner_id = hub_auth.current_user_id()
      OR hub_auth.has_app_role(app_id, ARRAY['admin', 'owner'])
    )
  );

CREATE POLICY app_usage_select_scoped
  ON public.app_usage
  FOR SELECT
  TO authenticated
  USING (
    app_id = hub_auth.current_app_id()
    AND hub_auth.is_active_app(app_id)
    AND hub_auth.has_active_membership(app_id, hub_auth.current_user_id())
  );

-- Ordinary clients cannot write directly to buckets, reservations, objects, or usage counters.
REVOKE ALL ON public.storage_buckets, public.quota_reservations, public.storage_objects, public.app_usage FROM PUBLIC, anon, authenticated;
GRANT SELECT ON public.storage_buckets, public.quota_reservations, public.storage_objects, public.app_usage TO authenticated;
GRANT ALL ON public.storage_buckets, public.quota_reservations, public.storage_objects, public.app_usage TO service_role;

-- Trusted server-side atomic storage reservation procedure
CREATE OR REPLACE FUNCTION hub_private.reserve_storage_upload(
  p_app_id text,
  p_user_id uuid,
  p_bucket_id text,
  p_relative_path text,
  p_mime_type text,
  p_size_bytes bigint,
  p_idempotency_key text DEFAULT NULL,
  p_ttl_seconds integer DEFAULT 300
)
RETURNS TABLE (
  reservation_id uuid,
  object_id uuid,
  object_path text,
  expires_at timestamptz,
  reused boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, hub_private
AS $$
#variable_conflict use_column
DECLARE
  v_app public.apps;
  v_bucket public.storage_buckets;
  v_membership public.app_memberships;
  v_existing_res public.quota_reservations;
  v_existing_obj public.storage_objects;
  v_app_used bigint;
  v_app_reserved bigint;
  v_user_used bigint;
  v_user_reserved bigint;
  v_res_id uuid;
  v_obj_id uuid;
  v_obj_path text;
  v_expires timestamptz;
BEGIN
  IF p_size_bytes IS NULL OR p_size_bytes <= 0 THEN
    RAISE EXCEPTION 'VALIDATION_ERROR: size_bytes must be a positive integer' USING ERRCODE = '22023';
  END IF;

  IF p_relative_path IS NULL
    OR p_relative_path !~ '^[a-zA-Z0-9._/-]{1,200}$'
    OR p_relative_path ~ '^/'
    OR p_relative_path ~ '/$'
    OR p_relative_path ~ '//'
    OR p_relative_path ~ '(^|/)\.\.?(/|$)'
    OR p_relative_path ~ '\\' THEN
    RAISE EXCEPTION 'INVALID_PATH: relative_path fails storage path validation' USING ERRCODE = '22023';
  END IF;

  -- Serialize concurrent quota checks per app and per user within this transaction.
  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('stor_app:' || p_app_id));
  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('stor_user:' || p_app_id || ':' || p_user_id::text));

  SELECT * INTO v_app FROM public.apps WHERE id = p_app_id;
  IF NOT FOUND OR v_app.status <> 'active' THEN
    RAISE EXCEPTION 'APP_INACTIVE: app not found or inactive' USING ERRCODE = '42501';
  END IF;

  SELECT * INTO v_membership
  FROM public.app_memberships
  WHERE app_id = p_app_id AND user_id = p_user_id AND status = 'active';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'FORBIDDEN: user is not an active member of this app' USING ERRCODE = '42501';
  END IF;

  IF NOT ('storage:write' = ANY(v_membership.capabilities) OR '*' = ANY(v_membership.capabilities)) THEN
    RAISE EXCEPTION 'FORBIDDEN: membership lacks storage:write capability' USING ERRCODE = '42501';
  END IF;

  SELECT * INTO v_bucket FROM public.storage_buckets WHERE id = p_bucket_id AND app_id = p_app_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'BUCKET_NOT_FOUND: bucket "%" does not belong to app "%"', p_bucket_id, p_app_id USING ERRCODE = '42501';
  END IF;

  IF p_size_bytes > v_app.max_upload_bytes THEN
    RAISE EXCEPTION 'UPLOAD_TOO_LARGE: % bytes exceeds max_upload_bytes (% bytes)', p_size_bytes, v_app.max_upload_bytes USING ERRCODE = 'P0001';
  END IF;

  IF NOT (p_mime_type = ANY(v_app.allowed_mime_types)) THEN
    RAISE EXCEPTION 'UNSUPPORTED_MEDIA_TYPE: mime_type "%" is not allowed for app "%"', p_mime_type, p_app_id USING ERRCODE = '22023';
  END IF;

  -- Expire stale reservations before checking remaining quota
  UPDATE public.quota_reservations qr
  SET status = 'expired'
  WHERE qr.app_id = p_app_id
    AND qr.status = 'reserved'
    AND qr.expires_at <= pg_catalog.now();

  -- Idempotency check
  IF p_idempotency_key IS NOT NULL THEN
    SELECT * INTO v_existing_res
    FROM public.quota_reservations qr
    WHERE qr.app_id = p_app_id
      AND qr.user_id = p_user_id
      AND qr.idempotency_key = p_idempotency_key
      AND qr.status = 'reserved'
      AND qr.expires_at > pg_catalog.now();

    IF FOUND THEN
      SELECT * INTO v_existing_obj
      FROM public.storage_objects so
      WHERE so.reservation_id = v_existing_res.id;

      IF FOUND AND v_existing_obj.status = 'pending' THEN
        RETURN QUERY SELECT v_existing_res.id, v_existing_obj.id, v_existing_obj.object_path, v_existing_res.expires_at, true;
        RETURN;
      END IF;
    END IF;
  END IF;

  v_obj_path := p_app_id || '/' || p_user_id::text || '/' || p_relative_path;

  IF EXISTS (
    SELECT 1 FROM public.storage_objects so
    WHERE so.bucket_id = p_bucket_id
      AND so.object_path = v_obj_path
      AND so.status IN ('active', 'pending')
  ) THEN
    RAISE EXCEPTION 'OBJECT_EXISTS: object already exists or upload is pending at this path' USING ERRCODE = '23505';
  END IF;

  -- Sum active storage and live unexpired reservations
  SELECT COALESCE(SUM(so.size_bytes), 0)::bigint INTO v_app_used
  FROM public.storage_objects so
  WHERE so.app_id = p_app_id AND so.status = 'active';

  SELECT COALESCE(SUM(qr.bytes_reserved), 0)::bigint INTO v_app_reserved
  FROM public.quota_reservations qr
  WHERE qr.app_id = p_app_id AND qr.status = 'reserved' AND qr.expires_at > pg_catalog.now();

  IF v_app_used + v_app_reserved + p_size_bytes > v_app.max_storage_bytes THEN
    RAISE EXCEPTION 'QUOTA_EXCEEDED: app storage quota exceeded (% used + % reserved + % requested > % max)',
      v_app_used, v_app_reserved, p_size_bytes, v_app.max_storage_bytes
      USING ERRCODE = 'P0001';
  END IF;

  SELECT COALESCE(SUM(so.size_bytes), 0)::bigint INTO v_user_used
  FROM public.storage_objects so
  WHERE so.app_id = p_app_id AND so.owner_id = p_user_id AND so.status = 'active';

  SELECT COALESCE(SUM(qr.bytes_reserved), 0)::bigint INTO v_user_reserved
  FROM public.quota_reservations qr
  WHERE qr.app_id = p_app_id AND qr.user_id = p_user_id AND qr.status = 'reserved' AND qr.expires_at > pg_catalog.now();

  IF v_user_used + v_user_reserved + p_size_bytes > v_app.max_user_storage_bytes THEN
    RAISE EXCEPTION 'QUOTA_EXCEEDED: user storage quota exceeded (% used + % reserved + % requested > % max)',
      v_user_used, v_user_reserved, p_size_bytes, v_app.max_user_storage_bytes
      USING ERRCODE = 'P0001';
  END IF;

  v_expires := pg_catalog.now() + pg_catalog.make_interval(secs => GREATEST(30, LEAST(p_ttl_seconds, 900)));

  INSERT INTO public.quota_reservations (app_id, user_id, bytes_reserved, idempotency_key, status, expires_at)
  VALUES (p_app_id, p_user_id, p_size_bytes, p_idempotency_key, 'reserved', v_expires)
  RETURNING id INTO v_res_id;

  -- Remove any previously deleted tombstone at the same path before creating pending object
  DELETE FROM public.storage_objects
  WHERE bucket_id = p_bucket_id AND object_path = v_obj_path AND status = 'deleted';

  INSERT INTO public.storage_objects (
    bucket_id, app_id, owner_id, relative_path, object_path,
    mime_type, size_bytes, status, reservation_id
  )
  VALUES (
    p_bucket_id, p_app_id, p_user_id, p_relative_path, v_obj_path,
    p_mime_type, p_size_bytes, 'pending', v_res_id
  )
  RETURNING id INTO v_obj_id;

  INSERT INTO public.app_usage (app_id, reserved_storage_bytes)
  VALUES (p_app_id, v_app_reserved + p_size_bytes)
  ON CONFLICT (app_id) DO UPDATE
  SET reserved_storage_bytes = v_app_reserved + p_size_bytes;

  RETURN QUERY SELECT v_res_id, v_obj_id, v_obj_path, v_expires, false;
END;
$$;

CREATE OR REPLACE FUNCTION hub_private.commit_storage_upload(
  p_object_id uuid,
  p_actual_size_bytes bigint,
  p_sha256 text
)
RETURNS public.storage_objects
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, hub_private
AS $$
DECLARE
  v_obj public.storage_objects;
  v_res public.quota_reservations;
BEGIN
  SELECT * INTO v_obj FROM public.storage_objects WHERE id = p_object_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'OBJECT_NOT_FOUND: storage object missing' USING ERRCODE = 'P0002';
  END IF;

  IF v_obj.status <> 'pending' THEN
    RAISE EXCEPTION 'INVALID_STATE: object status is "%", expected pending', v_obj.status USING ERRCODE = 'P0001';
  END IF;

  SELECT * INTO v_res FROM public.quota_reservations WHERE id = v_obj.reservation_id FOR UPDATE;
  IF NOT FOUND OR v_res.status <> 'reserved' OR v_res.expires_at <= pg_catalog.now() THEN
    RAISE EXCEPTION 'RESERVATION_EXPIRED: upload reservation is missing or expired' USING ERRCODE = 'P0001';
  END IF;

  IF p_actual_size_bytes <= 0 OR p_actual_size_bytes > v_res.bytes_reserved THEN
    RAISE EXCEPTION 'SIZE_MISMATCH: actual upload size (%) exceeds reserved size (%)', p_actual_size_bytes, v_res.bytes_reserved
      USING ERRCODE = 'P0001';
  END IF;

  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('stor_app:' || v_obj.app_id));

  UPDATE public.storage_objects
  SET status = 'active',
      size_bytes = p_actual_size_bytes,
      sha256 = p_sha256
  WHERE id = v_obj.id
  RETURNING * INTO v_obj;

  UPDATE public.quota_reservations
  SET status = 'committed'
  WHERE id = v_res.id;

  PERFORM hub_private.reconcile_app_usage(v_obj.app_id);

  RETURN v_obj;
END;
$$;

CREATE OR REPLACE FUNCTION hub_private.reconcile_app_usage(p_app_id text DEFAULT NULL)
RETURNS TABLE (
  app_id text,
  active_storage_bytes bigint,
  reserved_storage_bytes bigint,
  active_object_count integer,
  record_count integer,
  expired_reservations integer
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, hub_private
AS $$
#variable_conflict use_column
DECLARE
  v_app RECORD;
  v_expired integer;
  v_active_bytes bigint;
  v_reserved_bytes bigint;
  v_obj_count integer;
  v_rec_count integer;
BEGIN
  FOR v_app IN
    SELECT a.id FROM public.apps a
    WHERE p_app_id IS NULL OR a.id = p_app_id
  LOOP
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('stor_app:' || v_app.id));

    WITH expired_rows AS (
      UPDATE public.quota_reservations qr
      SET status = 'expired'
      WHERE qr.app_id = v_app.id
        AND qr.status = 'reserved'
        AND qr.expires_at <= pg_catalog.now()
      RETURNING qr.id
    )
    SELECT count(*)::integer INTO v_expired FROM expired_rows;

    -- Clean pending objects whose reservation expired or was released
    UPDATE public.storage_objects so
    SET status = 'deleted'
    FROM public.quota_reservations qr
    WHERE so.reservation_id = qr.id
      AND so.app_id = v_app.id
      AND so.status = 'pending'
      AND qr.status IN ('expired', 'released');

    SELECT COALESCE(SUM(so.size_bytes), 0)::bigint, COUNT(*)::integer
    INTO v_active_bytes, v_obj_count
    FROM public.storage_objects so
    WHERE so.app_id = v_app.id AND so.status = 'active';

    SELECT COALESCE(SUM(qr.bytes_reserved), 0)::bigint
    INTO v_reserved_bytes
    FROM public.quota_reservations qr
    WHERE qr.app_id = v_app.id AND qr.status = 'reserved' AND qr.expires_at > pg_catalog.now();

    SELECT COUNT(*)::integer INTO v_rec_count
    FROM public.app_records ar
    WHERE ar.app_id = v_app.id;

    INSERT INTO public.app_usage (
      app_id, active_storage_bytes, reserved_storage_bytes,
      active_object_count, record_count, last_reconciled_at
    )
    VALUES (
      v_app.id, v_active_bytes, v_reserved_bytes,
      v_obj_count, v_rec_count, pg_catalog.now()
    )
    ON CONFLICT ON CONSTRAINT app_usage_pkey DO UPDATE
    SET active_storage_bytes = EXCLUDED.active_storage_bytes,
        reserved_storage_bytes = EXCLUDED.reserved_storage_bytes,
        active_object_count = EXCLUDED.active_object_count,
        record_count = EXCLUDED.record_count,
        last_reconciled_at = EXCLUDED.last_reconciled_at;

    reconcile_app_usage.app_id := v_app.id;
    reconcile_app_usage.active_storage_bytes := v_active_bytes;
    reconcile_app_usage.reserved_storage_bytes := v_reserved_bytes;
    reconcile_app_usage.active_object_count := v_obj_count;
    reconcile_app_usage.record_count := v_rec_count;
    reconcile_app_usage.expired_reservations := v_expired;
    RETURN NEXT;
  END LOOP;
END;
$$;

REVOKE ALL ON FUNCTION hub_private.reserve_storage_upload(text, uuid, text, text, text, bigint, text, integer) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION hub_private.commit_storage_upload(uuid, bigint, text) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION hub_private.reconcile_app_usage(text) FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION hub_private.reserve_storage_upload(text, uuid, text, text, text, bigint, text, integer) TO service_role;
GRANT EXECUTE ON FUNCTION hub_private.commit_storage_upload(uuid, bigint, text) TO service_role;
GRANT EXECUTE ON FUNCTION hub_private.reconcile_app_usage(text) TO service_role;
