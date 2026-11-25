import { HubError, TimeoutError, NetworkError, mapHttpError } from './errors.js';

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function requestWithRetry(
  fetchImpl,
  url,
  {
    method = 'GET',
    headers = {},
    body = undefined,
    timeoutMs = 8000,
    maxRetries = 2,
    idempotent = undefined,
    idempotencyKey = null,
    responseType = 'json',
  } = {}
) {
  const upperMethod = method.toUpperCase();
  const isSafeToRetry =
    idempotent !== undefined
      ? Boolean(idempotent)
      : upperMethod === 'GET' || upperMethod === 'HEAD' || Boolean(idempotencyKey);
  const attempts = isSafeToRetry ? Math.max(1, maxRetries + 1) : 1;

  let lastError;
  for (let attempt = 0; attempt < attempts; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const mergedHeaders = { ...headers };
      if (idempotencyKey) {
        mergedHeaders['Idempotency-Key'] = idempotencyKey;
      }
      const resp = await fetchImpl(url, {
        method: upperMethod,
        headers: mergedHeaders,
        body,
        signal: controller.signal,
      });

      clearTimeout(timer);

      if (!resp.ok) {
        let payload = null;
        try {
          payload = await resp.json();
        } catch {
          payload = null;
        }
        const err = mapHttpError(resp.status, payload);
        if (err.retryable && attempt + 1 < attempts && isSafeToRetry) {
          lastError = err;
          await sleep(100 * 2 ** attempt);
          continue;
        }
        throw err;
      }

      if (responseType === 'bytes') {
        const ab = await resp.arrayBuffer();
        return {
          bytes: new Uint8Array(ab),
          contentType: resp.headers.get('content-type') || 'application/octet-stream',
        };
      }

      if (resp.status === 204) return null;
      return await resp.json();
    } catch (err) {
      clearTimeout(timer);
      if (err instanceof HubError) {
        throw err;
      }
      if (err?.name === 'AbortError') {
        lastError = new TimeoutError(`Request timed out after ${timeoutMs}ms`, timeoutMs);
      } else {
        lastError = new NetworkError(`Network failure: ${err?.message ?? 'unknown error'}`, err);
      }

      if (!isSafeToRetry || attempt + 1 >= attempts) {
        throw lastError;
      }
      await sleep(100 * 2 ** attempt);
    }
  }

  throw lastError;
}
