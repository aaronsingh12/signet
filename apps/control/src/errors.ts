// A refusal that cites the rule behind it, so every 4xx is explainable. Rendered as RFC 9457
// problem details by the error handler in http.ts.
export class PolicyError extends Error {
  constructor(
    readonly rule: string,
    message: string,
    readonly status = 422,
    readonly extra: Record<string, unknown> = {},
  ) {
    super(message);
  }
}

export const notFound = (what: string) => new PolicyError('NOT_FOUND', `${what} not found`, 404);
export const forbidden = (rule: string, message: string) => new PolicyError(rule, message, 403);
export const invalid = (message: string) => new PolicyError('VALIDATION', message, 400);
