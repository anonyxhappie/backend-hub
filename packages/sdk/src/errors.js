export class HubError extends Error {
  constructor(message, { code = 'HUB_ERROR', status = 0, details = undefined, retryable = false } = {}) {
    super(message);
    this.name = this.constructor.name;
    this.code = code;
    this.status = status;
    this.details = details;
    this.retryable = retryable;
  }
}

export class ConfigError extends HubError {
  constructor(message, details) {
    super(message, { code: 'CONFIG_ERROR', status: 0, details, retryable: false });
  }
}

export class AuthError extends HubError {
  constructor(message, status = 401, code = 'AUTH_ERROR', details) {
    super(message, { code, status, details, retryable: false });
  }
}

export class AuthorizationError extends HubError {
  constructor(message, status = 403, code = 'FORBIDDEN', details) {
    super(message, { code, status, details, retryable: false });
  }
}

export class QuotaError extends HubError {
  constructor(message, status = 429, code = 'QUOTA_EXCEEDED', details) {
    super(message, { code, status, details, retryable: false });
  }
}

export class RateLimitError extends HubError {
  constructor(message, status = 429, details) {
    super(message, { code: 'RATE_LIMITED', status, details, retryable: true });
  }
}

export class ValidationError extends HubError {
  constructor(message, status = 400, code = 'VALIDATION_ERROR', details) {
    super(message, { code, status, details, retryable: false });
  }
}

export class NotFoundError extends HubError {
  constructor(message, status = 404, details) {
    super(message, { code: 'NOT_FOUND', status, details, retryable: false });
  }
}

export class TimeoutError extends HubError {
  constructor(message, timeoutMs) {
    super(message, { code: 'TIMEOUT', status: 0, details: { timeoutMs }, retryable: true });
  }
}

export class NetworkError extends HubError {
  constructor(message, cause) {
    super(message, { code: 'NETWORK_ERROR', status: 0, details: { cause: cause?.message }, retryable: true });
  }
}

export function mapHttpError(status, body) {
  const errObj = body?.error ?? {};
  const code = errObj.code ?? 'HTTP_ERROR';
  const message = errObj.message ?? `Request failed with status ${status}`;
  const details = errObj.details;

  if (code === 'QUOTA_EXCEEDED' || code === 'UPLOAD_TOO_LARGE') {
    return new QuotaError(message, status, code, details);
  }
  if (code === 'RATE_LIMITED') {
    return new RateLimitError(message, status, details);
  }
  if (status === 401 || code === 'AUTH_REQUIRED' || code === 'AUTH_INVALID') {
    return new AuthError(message, status, code, details);
  }
  if (status === 403) {
    return new AuthorizationError(message, status, code, details);
  }
  if (status === 404) {
    return new NotFoundError(message, status, details);
  }
  if (status === 400 || status === 409 || status === 413) {
    return new ValidationError(message, status, code, details);
  }
  const retryable = status >= 500 && status <= 599;
  return new HubError(message, { code, status, details, retryable });
}
