/**
 * Helpers for the "what will change" part of an approval prompt.
 *
 * A prompt that only echoes the new values makes the human guess what they are replacing. These helpers
 * render `current → new` per field, and pin the approval to the very state that was rendered.
 */

/** A value as a human reads it in a prompt: null / undefined are "unset", lists are comma-joined, objects are JSON. */
export function show(v: unknown): string {
  if (v === null || v === undefined) return "unset";
  if (Array.isArray(v)) return v.length ? v.map(show).join(", ") : "none";
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

function same(a: unknown, b: unknown): boolean {
  return JSON.stringify(a ?? null) === JSON.stringify(b ?? null);
}

/** `old → new`, or `value (unchanged)` when the call would not move it. */
export function change(current: unknown, next: unknown): string {
  return same(current, next) ? `${show(current)} (unchanged)` : `${show(current)} → ${show(next)}`;
}

/**
 * A probe that first returns the version of the state the human was SHOWN, and re-reads GitHub afterwards.
 * The confirmer reads the probe before the prompt and again after the answer, so the second read is
 * compared against exactly the snapshot the prompt was rendered from, not a later one.
 */
export function pinned(shown: string | undefined, fresh: () => Promise<string | undefined>): () => Promise<string | undefined> {
  let first = true;
  return async () => {
    if (first) {
      first = false;
      return shown;
    }
    return fresh();
  };
}
