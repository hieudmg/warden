import { render, screen, waitFor, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest"
import { App } from "./app"

// Keep the production API client and all views: only replace the HTTP boundary.
const profile = { id: 1, name: "imported-api", origin: "http://127.0.0.1:9000", auth_type: "bearer", note: "Ops", group_id: 1, group_name: "prod", has_credential: true, has_username: false, has_password: false, archived: false, created_at: "2026-11-17T00:00:00Z", updated_at: "2026-11-17T00:00:00Z" }
let imported = false
let groupDeleted = false
let groupName = "prod"
let credentials = "saved-token"
const calls: { path: string; method: string; payload?: Record<string, unknown> }[] = []
function json(body: unknown, status = 200) { return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } }) }

beforeEach(() => {
  imported = false; groupDeleted = false; groupName = "prod"; credentials = "saved-token"; calls.length = 0
  window.history.replaceState({}, "", "/http")
  vi.stubGlobal("fetch", vi.fn(async (path: string, init?: RequestInit) => {
    const method = init?.method ?? "GET"
    const payload = init?.body ? JSON.parse(String(init.body)) : undefined
    calls.push({ path, method, payload })
    if (path === "/api/v1/http-connections") return json(imported ? [{ ...profile, group_id: groupDeleted ? 0 : 1, group_name: groupDeleted ? undefined : groupName }] : [])
    if (path === "/api/v1/http-connections/1" && method === "PUT") {
      if (payload.credential !== undefined) credentials = payload.credential
      return json(profile)
    }
    if (path === "/api/v1/groups") return json(groupDeleted ? [] : [{ id: 1, name: groupName, ssh_connection_count: 0, db_connection_count: 0, http_connection_count: imported ? 1 : 0, created_at: profile.created_at, updated_at: profile.updated_at }])
    if (path === "/api/v1/groups/1/dependents") return json({ ssh: [], db: [], http: [{ id: 1, name: profile.name }] })
    if (path === "/api/v1/groups/1" && method === "PUT") { groupName = payload.name; return json({ id: 1, name: groupName }) }
    if (path === "/api/v1/groups/1" && method === "DELETE") { groupDeleted = true; return new Response(null, { status: 204 }) }
    if (path === "/api/v1/data/import" && method === "POST") { imported = true; return json({ imported: true }) }
    if (["/api/v1/ssh-connections", "/api/v1/db-connections", "/api/v1/key-pairs", "/api/v1/projects"].includes(path)) return json([])
    throw new Error(`Unexpected API request: ${method} ${path}`)
  }))
})
afterEach(() => vi.unstubAllGlobals())

describe("App HTTP integration", () => {
  test("loads direct /http route, imports then refreshes HTTP and every list through production API client", async () => {
    const user = userEvent.setup()
    render(<App />)
    expect(window.location.pathname).toBe("/http")
    expect(screen.getByRole("tab", { name: "HTTP" })).toHaveAttribute("aria-selected", "true")
    expect(await screen.findByText("No HTTP connections yet.")).toBeInTheDocument()
    await user.click(screen.getByRole("button", { name: "Import data" }))
    const dialog = await screen.findByRole("dialog")
    expect(within(dialog).getByText(/plaintext credentials/)).toBeInTheDocument()
    await user.upload(within(dialog).getByLabelText("Export file"), new File(['{"format":"warden-data","version":1}'], "warden-data.json", { type: "application/json" }))
    await user.click(within(dialog).getByRole("button", { name: "Import" }))
    expect(await screen.findByText("imported-api")).toBeInTheDocument()
    for (const path of ["http-connections", "ssh-connections", "db-connections", "groups", "key-pairs", "projects"]) {
      expect(calls.filter(call => call.path === `/api/v1/${path}` && call.method === "GET")).toHaveLength(2)
    }
    await user.click(screen.getByRole("button", { name: "Edit imported-api" }))
    const edit = await screen.findByRole("dialog")
    expect(within(edit).getByLabelText("Credential")).toHaveValue("")
    await user.click(within(edit).getByRole("button", { name: "Save" }))
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument())
    expect(calls.find(call => call.path === "/api/v1/http-connections/1")?.payload).toEqual({ name: profile.name, origin: profile.origin, auth_type: "bearer", note: "Ops", group_id: 1 })
    expect(credentials).toBe("saved-token")
    expect(calls.filter(call => call.path === "/api/v1/groups" && call.method === "GET")).toHaveLength(3)
  })

  test("shared group rename/delete reloads HTTP labels and counts with dependent warning", async () => {
    imported = true
    const user = userEvent.setup()
    render(<App />)
    expect(await screen.findByText("imported-api")).toBeInTheDocument()
    await user.click(screen.getByRole("tab", { name: "Groups" }))
    expect(screen.getByText("SSH 0 · DB 0 · HTTP 1")).toBeInTheDocument()
    await user.click(screen.getByRole("button", { name: "Edit prod" }))
    let dialog = await screen.findByRole("dialog")
    await user.clear(within(dialog).getByLabelText("Name"))
    await user.type(within(dialog).getByLabelText("Name"), "renamed")
    await user.click(within(dialog).getByRole("button", { name: "Save" }))
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument())
    await user.click(screen.getByRole("tab", { name: "HTTP" }))
    expect(await screen.findByText("renamed")).toBeInTheDocument()
    await user.click(screen.getByRole("tab", { name: "Groups" }))
    await user.click(screen.getByRole("button", { name: "Delete renamed" }))
    dialog = await screen.findByRole("dialog")
    expect(await within(dialog).findByText("imported-api (HTTP)")).toBeInTheDocument()
    await user.click(within(dialog).getByRole("button", { name: "Delete" }))
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument())
    await user.click(screen.getByRole("tab", { name: "HTTP" }))
    expect(await screen.findByText("(Ungrouped)")).toBeInTheDocument()
  })
})
