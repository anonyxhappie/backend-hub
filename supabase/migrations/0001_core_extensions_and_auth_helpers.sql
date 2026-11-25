-- 0001_core_extensions_and_auth_helpers.sql
-- Establishes internal schemas, PostgreSQL roles (when not pre-created by Supabase),
-- safe default privileges, and trusted app-context claim helpers.
-- Note: gen_random_uuid() is built into PostgreSQL 13+ core (pg_catalog) without requiring pgcrypto.

CREATE SCHEMA IF NOT EXISTS hub_auth;
CREATE SCHEMA IF NOT EXISTS hub_private;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    CREATE ROLE anon NOLOGIN NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    CREATE ROLE authenticated NOLOGIN NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
    CREATE ROLE service_role NOLOGIN NOINHERIT BYPASSRLS;
  END IF;
END
$$;

-- Minimal auth.users table for standalone PostgreSQL / PGlite environments.
-- On hosted/local Supabase, the auth schema and auth.users already exist and are owned by supabase_auth_admin.
DO $$
BEGIN
  IF to_regclass('auth.users') IS NULL THEN
    CREATE SCHEMA IF NOT EXISTS auth;
    REVOKE ALL ON SCHEMA auth FROM PUBLIC, anon, authenticated;
    GRANT USAGE ON SCHEMA auth TO service_role;

    CREATE TABLE auth.users (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      email text NOT NULL UNIQUE,
      password_hash text NOT NULL,
      email_confirmed_at timestamptz DEFAULT now(),
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now()
    );

    REVOKE ALL ON auth.users FROM PUBLIC, anon, authenticated;
    GRANT ALL ON auth.users TO service_role;
  END IF;
END
$$;

-- Harden schema privileges
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role;

REVOKE ALL ON SCHEMA hub_private FROM PUBLIC, anon, authenticated;
GRANT USAGE ON SCHEMA hub_private TO service_role;

REVOKE ALL ON SCHEMA hub_auth FROM PUBLIC;
GRANT USAGE ON SCHEMA hub_auth TO anon, authenticated, service_role;

ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM PUBLIC, anon, authenticated;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM PUBLIC, anon, authenticated;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON FUNCTIONS FROM PUBLIC, anon, authenticated;

-- Reads verified JWT claims set exclusively by the trusted API gateway / PostgREST layer.
CREATE OR REPLACE FUNCTION hub_auth.jwt_claims()
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
  SELECT COALESCE(
    NULLIF(pg_catalog.current_setting('request.jwt.claims', true), '')::jsonb,
    '{}'::jsonb
  );
$$;

-- Authenticated user UUID from verified JWT `sub` claim. Returns NULL for anonymous or malformed values.
CREATE OR REPLACE FUNCTION hub_auth.current_user_id()
RETURNS uuid
LANGUAGE plpgsql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog, hub_auth
AS $$
DECLARE
  raw_sub text;
BEGIN
  raw_sub := NULLIF(hub_auth.jwt_claims() ->> 'sub', '');
  IF raw_sub IS NULL THEN
    RETURN NULL;
  END IF;
  RETURN raw_sub::uuid;
EXCEPTION
  WHEN invalid_text_representation THEN
    RETURN NULL;
END;
$$;

-- Returns the verified app_id ONLY when the server-minted app context claim is marked verified and unexpired.
-- Never reads client-supplied query params, headers, or request body fields.
CREATE OR REPLACE FUNCTION hub_auth.current_app_id()
RETURNS text
LANGUAGE plpgsql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog, hub_auth
AS $$
DECLARE
  claims jsonb;
  app_id_val text;
  exp_val bigint;
BEGIN
  claims := hub_auth.jwt_claims();
  IF COALESCE(claims ->> 'app_ctx_verified', 'false') <> 'true' THEN
    RETURN NULL;
  END IF;

  app_id_val := NULLIF(claims ->> 'app_id', '');
  IF app_id_val IS NULL THEN
    RETURN NULL;
  END IF;

  BEGIN
    exp_val := COALESCE((claims ->> 'app_ctx_exp')::bigint, 0);
  EXCEPTION
    WHEN invalid_text_representation THEN
      RETURN NULL;
  END;

  IF exp_val <= EXTRACT(EPOCH FROM pg_catalog.clock_timestamp())::bigint THEN
    RETURN NULL;
  END IF;

  RETURN app_id_val;
END;
$$;

-- Returns verified capabilities from the server-minted app context claim.
CREATE OR REPLACE FUNCTION hub_auth.current_app_capabilities()
RETURNS text[]
LANGUAGE plpgsql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog, hub_auth
AS $$
DECLARE
  claims jsonb;
  caps_json jsonb;
BEGIN
  IF hub_auth.current_app_id() IS NULL THEN
    RETURN ARRAY[]::text[];
  END IF;

  claims := hub_auth.jwt_claims();
  caps_json := claims -> 'app_caps';
  IF caps_json IS NULL OR pg_catalog.jsonb_typeof(caps_json) <> 'array' THEN
    RETURN ARRAY[]::text[];
  END IF;

  RETURN ARRAY(
    SELECT pg_catalog.jsonb_array_elements_text(caps_json)
  );
END;
$$;

CREATE OR REPLACE FUNCTION hub_auth.has_capability(required_cap text)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog, hub_auth
AS $$
  SELECT
    hub_auth.current_app_id() IS NOT NULL
    AND (
      required_cap = ANY(hub_auth.current_app_capabilities())
      OR '*' = ANY(hub_auth.current_app_capabilities())
    );
$$;

REVOKE ALL ON FUNCTION hub_auth.jwt_claims() FROM PUBLIC;
REVOKE ALL ON FUNCTION hub_auth.current_user_id() FROM PUBLIC;
REVOKE ALL ON FUNCTION hub_auth.current_app_id() FROM PUBLIC;
REVOKE ALL ON FUNCTION hub_auth.current_app_capabilities() FROM PUBLIC;
REVOKE ALL ON FUNCTION hub_auth.has_capability(text) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION hub_auth.jwt_claims() TO anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION hub_auth.current_user_id() TO anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION hub_auth.current_app_id() TO anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION hub_auth.current_app_capabilities() TO anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION hub_auth.has_capability(text) TO anon, authenticated, service_role;

-- Generic updated_at trigger helper
CREATE OR REPLACE FUNCTION hub_auth.touch_updated_at()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
BEGIN
  NEW.updated_at := pg_catalog.now();
  RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION hub_auth.touch_updated_at() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION hub_auth.touch_updated_at() TO authenticated, service_role;
