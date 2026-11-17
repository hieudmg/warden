import { render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { describe, expect, test, vi } from "vitest"
import type { HTTPConnection } from "@/api/types"
import { HTTPForm } from "./http-form"

const connection: HTTPConnection = {
  id: 1, name: "service", origin: "https://private.example:8443", auth_type: "basic",
  note: "Operations", group_id: 3, has_credential: false, has_username: true,
  has_password: true, archived: false, created_at: "2026-11-17T00:00:00Z", updated_at: "2026-11-17T00:00:00Z",
}
const group = { id: 3, name: "prod", ssh_connection_count: 0, db_connection_count: 0, http_connection_count: 1, created_at: connection.created_at, updated_at: connection.updated_at }

function setup(profile: HTTPConnection | null = connection) {
  const onSubmit = vi.fn()
  const user = userEvent.setup()
  render(<HTTPForm connection={profile} groups={[group]} pending={false} error={null} onSubmit={onSubmit} onCancel={() => {}} />)
  return { user, onSubmit }
}

describe("HTTPForm", () => {
  test("masks Basic username and password, shows only presence, and omits unchanged secrets", async () => {
    const { user, onSubmit } = setup()
    for (const label of ["Username", "Password"]) {
      expect(screen.getByLabelText(label)).toHaveValue("")
      expect(screen.getByLabelText(label)).toHaveAttribute("type", "password")
    }
    expect(screen.getByText("Username saved")).toBeInTheDocument()
    expect(screen.getByText("Password saved")).toBeInTheDocument()
    await user.click(screen.getByRole("button", { name: "Save" }))
    expect(onSubmit).toHaveBeenCalledWith({ name: "service", origin: connection.origin, auth_type: "basic", note: "Operations", group_id: 3 })
  })

  test.each(["bearer", "x_api_key"] as const)("sends only verbatim %s credential and selected group/notes", async auth_type => {
    const { user, onSubmit } = setup({ ...connection, auth_type, has_credential: true })
    expect(screen.getByText("Credential saved")).toBeInTheDocument()
    expect(screen.getByLabelText("Credential")).toHaveAttribute("type", "password")
    await user.type(screen.getByLabelText("Credential"), " token with spaces ")
    await user.click(screen.getByRole("button", { name: "Save" }))
    expect(onSubmit).toHaveBeenCalledWith({ name: "service", origin: connection.origin, auth_type, note: "Operations", group_id: 3, credential: " token with spaces " })
  })

  test("rotates one Basic field while preserving the other", async () => {
    const { user, onSubmit } = setup()
    await user.type(screen.getByLabelText("Password"), "replacement")
    await user.click(screen.getByRole("button", { name: "Save" }))
    expect(onSubmit.mock.calls[0][0]).toEqual({ name: "service", origin: connection.origin, auth_type: "basic", note: "Operations", group_id: 3, password: "replacement" })
  })

  test("clears all local secrets on every auth switch, including bearer to X-API-Key", async () => {
    const { user, onSubmit } = setup()
    await user.type(screen.getByLabelText("Username"), "stale-user")
    await user.type(screen.getByLabelText("Password"), "stale-password")
    await user.click(screen.getByRole("radio", { name: "Bearer" }))
    expect(screen.queryByText("Username saved")).not.toBeInTheDocument()
    await user.type(screen.getByLabelText("Credential"), "stale-bearer")
    await user.click(screen.getByRole("radio", { name: "X-API-Key" }))
    expect(screen.getByLabelText("Credential")).toHaveValue("")
    await user.click(screen.getByRole("radio", { name: "Basic" }))
    expect(screen.getByLabelText("Username")).toHaveValue("")
    expect(screen.getByLabelText("Password")).toHaveValue("")
    await user.click(screen.getByRole("button", { name: "Save" }))
    expect(onSubmit.mock.calls[0][0]).not.toHaveProperty("username")
    expect(onSubmit.mock.calls[0][0]).not.toHaveProperty("password")
    expect(onSubmit.mock.calls[0][0]).not.toHaveProperty("credential")
  })

  test("creates with origin-only guidance, exactly three auth modes, and HTTP exposure warning", async () => {
    const { user, onSubmit } = setup(null)
    expect(screen.getAllByRole("radio")).toHaveLength(3)
    await user.type(screen.getByLabelText("Name"), "local-api")
    await user.type(screen.getByLabelText("Origin"), "http://127.0.0.1:9000")
    expect(screen.getByText(/HTTP is unencrypted/)).toBeInTheDocument()
    expect(screen.getByText(/No path, query/)).toBeInTheDocument()
    await user.type(screen.getByLabelText("Note"), "Local development")
    await user.click(screen.getByRole("button", { name: "Save" }))
    expect(onSubmit).toHaveBeenCalledWith({ name: "local-api", origin: "http://127.0.0.1:9000", auth_type: "bearer", note: "Local development", group_id: 0 })
  })

  test("allows choosing a shared group and preserves missing assignments visibly", async () => {
    const { user, onSubmit } = setup({ ...connection, group_id: 99 })
    expect(screen.getByRole("combobox", { name: "Group" })).toHaveTextContent("Missing group #99")
    await user.click(screen.getByRole("combobox", { name: "Group" }))
    await user.click(await screen.findByRole("option", { name: "prod" }))
    await user.click(screen.getByRole("button", { name: "Save" }))
    expect(onSubmit.mock.calls[0][0].group_id).toBe(3)
  })

  test("disables submit/cancel and fields while pending and displays server validation errors", () => {
    render(<HTTPForm connection={connection} groups={[]} pending error="invalid origin" onSubmit={vi.fn()} onCancel={vi.fn()} />)
    expect(screen.getByRole("alert")).toHaveTextContent("invalid origin")
    expect(screen.getByRole("button", { name: "Saving" })).toBeDisabled()
    expect(screen.getByRole("button", { name: "Cancel" })).toBeDisabled()
    expect(screen.getByLabelText("Username")).toBeDisabled()
  })
})
