import type { SSHConnection } from "@/api/types"

/**
 * Parse the stored `jump_connection_ids` JSON array. The API accepts any
 * syntactically valid ordered integer sequence and postpones graph
 * validation until transport resolution, so duplicate, self, cyclic,
 * missing, zero, and negative IDs are all preserved verbatim.
 * Malformed JSON and non-integer elements return an empty route.
 */
export function parseJumpRoute(raw: string): number[] {
  try {
    const value: unknown = JSON.parse(raw)
    if (!Array.isArray(value)) return []
    if (!value.every(item => typeof item === "number" && Number.isInteger(item))) return []
    return value
  } catch {
    return []
  }
}

/** Serializes the visible order into the canonical JSON string format. */
export function serializeJumpRoute(ids: readonly number[]): string {
  return JSON.stringify(ids)
}

/** Immutable reorder; no-op and out-of-bounds moves return a copy. */
export function moveJump(ids: readonly number[], from: number, to: number): number[] {
  if (from === to || from < 0 || to < 0 || from >= ids.length || to >= ids.length) return [...ids]
  const next = [...ids]
  const [item] = next.splice(from, 1)
  next.splice(to, 0, item)
  return next
}

/** Display label for one route entry. */
export function jumpLabel(
  id: number,
  profiles: readonly SSHConnection[],
  editingID?: number,
): string {
  if (id === editingID) return "self (current connection)"
  const profile = profiles.find(p => p.id === id)
  return profile ? profile.name : `Missing SSH #${id}`
}

/** Option label for one jump-route candidate in the Add picker, appending
 * the profile's group name when it is grouped. */
export function jumpOptionLabel(profile: SSHConnection): string {
  const base = `${profile.name} — ${profile.host}:${profile.port}`
  return profile.group_name ? `${base} (${profile.group_name})` : base
}

/**
 * Profiles that may be appended to the route: the profile being edited and
 * every profile already selected are excluded so the UI cannot create a new
 * self-reference or duplicate. Existing exceptional entries stay untouched.
 */
export function jumpCandidates(
  profiles: readonly SSHConnection[],
  selectedIDs: readonly number[],
  editingID?: number,
): SSHConnection[] {
  const unavailable = new Set(selectedIDs)
  if (editingID !== undefined) unavailable.add(editingID)
  return profiles.filter(profile => !unavailable.has(profile.id))
}
