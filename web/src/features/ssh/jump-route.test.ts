import { describe, expect, test } from "vitest"
import type { SSHConnection } from "@/api/types"
import {
  jumpCandidates,
  jumpLabel,
  jumpOptionLabel,
  moveJump,
  parseJumpRoute,
  serializeJumpRoute,
} from "./jump-route"

function ssh(id: number, name: string, overrides: Partial<SSHConnection> = {}): SSHConnection {
  return {
    id,
    name,
    host: `${name}.example`,
    port: 22,
    username: "root",
    has_password: true,
    has_private_key: false,
    has_private_key_passphrase: false,
    proxy_host: "",
    proxy_port: 0,
    proxy_username: "",
    has_proxy_password: false,
    jump_connection_ids: "[]",
    default_dir: "",
    group_id: 0,
    group_name: "",
    created_at: "2026-08-24T00:00:00Z",
    updated_at: "2026-08-24T00:00:00Z",
    ...overrides,
  }
}

// Exceptional stored route: duplicate 2, self 7 (editing profile),
// missing 99, zero, negative, all preserved verbatim.
const exceptional = "[2,7,2,0,-4,99]"
const profiles = [ssh(2, "jump-a"), ssh(7, "bastion")]

describe("parseJumpRoute / serializeJumpRoute", () => {
  test("round-trips a valid stored route byte-normalized", () => {
    expect(parseJumpRoute(exceptional)).toEqual([2, 7, 2, 0, -4, 99])
    expect(serializeJumpRoute(parseJumpRoute(exceptional))).toBe(exceptional)
  })

  test("rejects malformed JSON defensively", () => {
    expect(parseJumpRoute("not json")).toEqual([])
    expect(parseJumpRoute("")).toEqual([])
    expect(parseJumpRoute("[1,")).toEqual([])
    expect(parseJumpRoute("null")).toEqual([])
    expect(parseJumpRoute("{}")).toEqual([])
  })

  test("rejects non-integer array elements", () => {
    expect(parseJumpRoute("[1,2.5]")).toEqual([])
    expect(parseJumpRoute("[1,\"two\"]")).toEqual([])
    expect(parseJumpRoute("[true]")).toEqual([])
  })

  test("accepts an empty route and serializes it canonically", () => {
    expect(parseJumpRoute("[]")).toEqual([])
    expect(serializeJumpRoute([])).toBe("[]")
  })
})

describe("moveJump", () => {
  test("moves an entry down and changes only requested positions", () => {
    expect(moveJump([2, 7, 2, 0, -4, 99], 0, 1)).toEqual([7, 2, 2, 0, -4, 99])
    expect(moveJump([2, 7, 2, 0, -4, 99], 4, 5)).toEqual([2, 7, 2, 0, 99, -4])
  })

  test("is immutable and no-op moves return a copy", () => {
    const input = [2, 7, 2, 0, -4, 99]
    const output = moveJump(input, 2, 2)
    expect(output).toEqual(input)
    expect(output).not.toBe(input)
  })

  test("out-of-bounds moves return a copy unchanged", () => {
    const input = [2, 7, 2, 0, -4, 99]
    expect(moveJump(input, -1, 1)).toEqual(input)
    expect(moveJump(input, 0, 99)).toEqual(input)
    expect(moveJump(input, 99, 0)).toEqual(input)
    expect(moveJump(input, 2, -3)).toEqual(input)
  })
})

describe("jumpLabel", () => {
  test("labels existing profiles by name", () => {
    expect(jumpLabel(2, profiles, 7)).toBe("jump-a")
  })

  test("marks the editing profile as a self reference", () => {
    expect(jumpLabel(7, profiles, 7)).toBe("self (current connection)")
  })

  test("labels unresolved IDs including zero and negatives", () => {
    expect(jumpLabel(0, profiles, 7)).toBe("Missing SSH #0")
    expect(jumpLabel(-4, profiles, 7)).toBe("Missing SSH #-4")
    expect(jumpLabel(99, profiles, 7)).toBe("Missing SSH #99")
  })

  test("labels a valid profile normally when editing another profile", () => {
    expect(jumpLabel(7, profiles, 3)).toBe("bastion")
  })
})

describe("jumpOptionLabel", () => {
  test("appends the group name to a grouped candidate's option label", () => {
    expect(jumpOptionLabel(ssh(2, "jump-a", { group_name: "prod" }))).toBe(
      "jump-a — jump-a.example:22 (prod)",
    )
  })

  test("keeps the option label unchanged for an ungrouped candidate", () => {
    expect(jumpOptionLabel(ssh(2, "jump-a"))).toBe("jump-a — jump-a.example:22")
  })
})

describe("jumpCandidates", () => {
  const roster = [ssh(2, "jump-a"), ssh(7, "bastion"), ssh(10, "storefront-jump")]

  test("excludes the editing profile and every selected existing ID", () => {
    const candidates = jumpCandidates(roster, [2, 0, -4, 99], 7)
    expect(candidates.map(c => c.id)).toEqual([10])
  })

  test("returns nothing when every profile is unavailable", () => {
    expect(jumpCandidates(roster, [2, 10], 7)).toEqual([])
  })

  test("without editingID only excludes selected IDs", () => {
    const candidates = jumpCandidates(roster, [10], undefined)
    expect(candidates.map(c => c.id)).toEqual([2, 7])
  })
})
