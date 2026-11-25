/**
 * Portfolio configuration helper demonstrating how 10–20 static apps share
 * Backend Hub without duplicating backend logic or embedding secrets.
 *
 * Each app supplies its explicit environment, API base URL, and appId.
 * Missing or unknown environments fail closed inside the SDK.
 */

export const PINNED_SDK_VERSION = '0.1.0';

export const ENVIRONMENTS = Object.freeze({
  local: Object.freeze({
    environment: 'local',
    baseUrl: 'http://127.0.0.1:4000',
  }),
  staging: Object.freeze({
    environment: 'staging',
    // Replace with your isolated staging project URL at deploy/build time; never fall back to production.
    baseUrl: '',
  }),
  production: Object.freeze({
    environment: 'production',
    // Replace with your isolated production HTTPS URL at build time.
    baseUrl: '',
  }),
});

export function resolveAppConfig({ appId, environment = 'local', baseUrlOverride = null }) {
  const envCfg = ENVIRONMENTS[environment];
  if (!envCfg) {
    throw new Error(`Unknown environment "${environment}". Failing closed.`);
  }
  const baseUrl = baseUrlOverride || envCfg.baseUrl;
  if (!baseUrl) {
    throw new Error(`No baseUrl configured for environment "${environment}". Failing closed.`);
  }
  return {
    environment: envCfg.environment,
    baseUrl,
    appId,
  };
}
