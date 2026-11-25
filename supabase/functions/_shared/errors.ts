export interface ErrorEnvelope {
  error: {
    code: string;
    message: string;
    status: number;
    details?: unknown;
  };
}

export function jsonResponse(status: number, body: unknown, headers: HeadersInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      ...headers,
    },
  });
}

export function errorResponse(
  status: number,
  code: string,
  message: string,
  details?: unknown,
  headers: HeadersInit = {}
): Response {
  const payload: ErrorEnvelope = { error: { code, message, status, ...(details ? { details } : {}) } };
  return jsonResponse(status, payload, headers);
}
