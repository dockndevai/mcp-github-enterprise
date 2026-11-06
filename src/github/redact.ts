/**
 * Secret redaction. GitHub responses can carry live credentials — webhook
 * `config.secret`/`token`/`password`, and the raw matched string in a
 * secret-scanning alert's `secret` field. These must never reach the model.
 *
 * Pure, defensive, and recursive: any object key that looks like a credential is
 * masked, wherever it appears in the payload. Benign metadata (e.g. the
 * `secret_type` of a scanning alert, or a webhook's non-secret config) is kept.
 */

const SECRET_KEYS = new Set([
  "secret",
  "token",
  "password",
  "client_secret",
  "private_key",
  "access_token",
  "refresh_token",
  "authorization",
]);

const MASK = "[REDACTED]";

export function redact<T>(value: T): T {
  return walk(value) as T;
}

function walk(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(walk);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (SECRET_KEYS.has(k.toLowerCase()) && v != null && v !== "") {
        out[k] = MASK;
      } else {
        out[k] = walk(v);
      }
    }
    return out;
  }
  return value;
}

/**
 * Trim a secret-scanning alert list to safe, useful fields. The raw `secret`
 * is dropped entirely (never masked-in-place, so it can't leak via nesting).
 */
export function redactSecretScanningAlerts(alerts: unknown): unknown {
  if (!Array.isArray(alerts)) return redact(alerts);
  return alerts.map((a) => {
    const alert = a as Record<string, unknown>;
    const { secret: _secret, ...rest } = alert;
    return redact(rest);
  });
}
