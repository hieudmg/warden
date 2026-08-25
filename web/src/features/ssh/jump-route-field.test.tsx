import { render, screen, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { describe, expect, test, vi } from "vitest"
import type { SSHConnection } from "@/api/types"
import { JumpRouteField } from "./jump-route-field"

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

// Editing profile is id 7 (self-reference), id 2 appears twice (duplicate),
// 99/0/-4 are missing, -4 and 99 are exceptional stored values.
const profiles = [ssh(2, "jump-a"), ssh(7, "bastion"), ssh(10, "storefront-jump")]
const exceptional: number[] = [2, 7, 2, 0, -4, 99]

describe("JumpRouteField", () => {
  test("renders every stored entry in order with accessible move/remove controls", () => {
    render(<JumpRouteField value={exceptional} onChange={vi.fn()} profiles={profiles} editingID={7} />)

    // Every entry renders; the duplicate renders twice.
    expect(screen.getByText("self (current connection)")).toBeInTheDocument()
    // Label text and the marker badge both carry the same missing text.
    expect(screen.getAllByText("Missing SSH #0")).toHaveLength(2)
    expect(screen.getAllByText("Missing SSH #-4")).toHaveLength(2)
    expect(screen.getAllByText("Missing SSH #99")).toHaveLength(2)
    expect(screen.getAllByText("jump-a")).toHaveLength(2)

    // Accessible names carry the visible label and the index.
    expect(screen.getByRole("button", { name: "Move jump-a 0 down" })).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Remove jump-a 2" })).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Move Missing SSH #-4 4 up" })).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Remove Missing SSH #99 5" })).toBeInTheDocument()
  })

  test("disables boundary moves", () => {
    render(<JumpRouteField value={exceptional} onChange={vi.fn()} profiles={profiles} editingID={7} />)

    expect(screen.getByRole("button", { name: "Move jump-a 0 up" })).toBeDisabled()
    expect(screen.getByRole("button", { name: "Move Missing SSH #99 5 down" })).toBeDisabled()
    expect(screen.getByRole("button", { name: "Move jump-a 0 down" })).toBeEnabled()
  })

  test("emits ordered onChange calls for move and remove", async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<JumpRouteField value={exceptional} onChange={onChange} profiles={profiles} editingID={7} />)

    await user.click(screen.getByRole("button", { name: "Move jump-a 0 down" }))
    expect(onChange).toHaveBeenNthCalledWith(1, [7, 2, 2, 0, -4, 99])

    await user.click(screen.getByRole("button", { name: "Remove Missing SSH #99 5" }))
    expect(onChange).toHaveBeenNthCalledWith(2, [2, 7, 2, 0, -4])
  })

  test("adds a candidate through the Add select and resets after selection", async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<JumpRouteField value={exceptional} onChange={onChange} profiles={profiles} editingID={7} />)

    const add = screen.getByRole("combobox", { name: "Add SSH profile to jump route" })
    await user.click(add)
    await user.click(await screen.findByRole("option", { name: "storefront-jump — storefront-jump.example:22" }))

    expect(onChange).toHaveBeenCalledTimes(1)
    expect(onChange).toHaveBeenCalledWith([2, 7, 2, 0, -4, 99, 10])
    // Select resets to placeholder after adding.
    expect(screen.getByRole("combobox", { name: "Add SSH profile to jump route" })).toHaveTextContent("Add")
  })

  test("filters jump-route candidates by search text", async () => {
    const user = userEvent.setup()
    render(<JumpRouteField value={[]} onChange={vi.fn()} profiles={profiles} />)

    await user.click(screen.getByRole("combobox", { name: "Add SSH profile to jump route" }))
    await user.type(await screen.findByPlaceholderText("Search SSH profiles"), "storefront")

    expect(screen.getByRole("option", { name: "storefront-jump — storefront-jump.example:22" })).toBeInTheDocument()
    expect(screen.queryByRole("option", { name: "jump-a — jump-a.example:22" })).not.toBeInTheDocument()
  })

  test("excludes self and already-selected profiles from Add options", async () => {
    const user = userEvent.setup()
    render(<JumpRouteField value={exceptional} onChange={vi.fn()} profiles={profiles} editingID={7} />)

    await user.click(screen.getByRole("combobox", { name: "Add SSH profile to jump route" }))
    expect(screen.queryByRole("option", { name: "jump-a — jump-a.example:22" })).not.toBeInTheDocument()
    expect(screen.queryByRole("option", { name: "bastion — bastion.example:22" })).not.toBeInTheDocument()
    expect(await screen.findByRole("option", { name: "storefront-jump — storefront-jump.example:22" })).toBeInTheDocument()
  })

  test("shows the group name on grouped candidate options", async () => {
    const user = userEvent.setup()
    const grouped = [ssh(2, "jump-a", { group_name: "prod" })]
    render(<JumpRouteField value={[]} onChange={vi.fn()} profiles={grouped} />)

    await user.click(screen.getByRole("combobox", { name: "Add SSH profile to jump route" }))
    expect(
      await screen.findByRole("option", { name: "jump-a — jump-a.example:22 (prod)" }),
    ).toBeInTheDocument()
  })

  test("disables Add when every profile is unavailable", () => {
    render(<JumpRouteField value={[2, 10]} onChange={vi.fn()} profiles={profiles} editingID={7} />)
    expect(screen.getByRole("combobox", { name: "Add SSH profile to jump route" })).toBeDisabled()
  })

  test("renders a badge next to the self reference and missing entries", () => {
    render(<JumpRouteField value={exceptional} onChange={vi.fn()} profiles={profiles} editingID={7} />)

    const selfRow = screen.getByText("self (current connection)").closest("li")
    expect(selfRow).not.toBeNull()
    expect(within(selfRow!).getByText("(current connection)")).toBeInTheDocument()

    const missingRow = screen.getAllByText("Missing SSH #99")[0].closest("li")
    expect(missingRow).not.toBeNull()
    // Row label plus its marker badge both display the same missing text.
    expect(within(missingRow!).getAllByText("Missing SSH #99")).toHaveLength(2)
  })
})
