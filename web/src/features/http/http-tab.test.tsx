import { render, screen, waitFor, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { beforeEach, describe, expect, test, vi } from "vitest"
import { api } from "@/api/client"
import type { HTTPConnection } from "@/api/types"
import type { ListResource } from "@/hooks/use-list-resource"
import { HTTPTab } from "./http-tab"

vi.mock("@/api/client", () => ({ api: { createHTTP: vi.fn(), updateHTTP: vi.fn(), deleteHTTP: vi.fn(), archiveHTTP: vi.fn() } }))
const mockedAPI = vi.mocked(api)
const profile: HTTPConnection = {
  id: 1, name: "service", origin: "http://localhost:9000", auth_type: "bearer", note: "Operations",
  group_id: 3, group_name: "prod", has_credential: true, has_username: false, has_password: false,
  archived: false, created_at: "2026-11-17T00:00:00Z", updated_at: "2026-11-17T00:00:00Z",
}
const notify = vi.fn()
function setup(overrides: Partial<ListResource<HTTPConnection>> = {}) {
  const resource: ListResource<HTTPConnection> = { data: [profile], loading: false, error: null, reload: vi.fn().mockResolvedValue(undefined), ...overrides }
  render(<HTTPTab resource={resource} groups={[]} notify={notify} />)
  return { user: userEvent.setup(), resource }
}
beforeEach(() => vi.resetAllMocks())

describe("HTTPTab", () => {
  test("renders group-first active/archive rows with notes, origin, auth and presence only", () => {
    setup({ data: [profile, { ...profile, id: 2, name: "old", archived: true, group_id: 0, group_name: undefined, auth_type: "basic", has_credential: false, has_username: true, has_password: false }] })
    expect(screen.getAllByRole("columnheader")[0]).toHaveTextContent("Group")
    expect(screen.getByText("prod")).toBeInTheDocument()
    expect(screen.getByText("(Ungrouped)")).toBeInTheDocument()
    expect(screen.getAllByText("Operations")).toHaveLength(2)
    expect(screen.getByText("Credential saved")).toBeInTheDocument()
    expect(screen.getByText("Username saved · Password missing")).toBeInTheDocument()
    expect(screen.getByRole("heading", { name: "Archived HTTP connections" })).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Edit old" })).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Delete old" })).toBeInTheDocument()
  })

  test("creates, reloads, notifies, and discards secrets when reopened", async () => {
    const { user, resource } = setup({ data: [] })
    mockedAPI.createHTTP.mockResolvedValue(profile)
    await user.click(screen.getByRole("button", { name: "New HTTP connection" }))
    let dialog = await screen.findByRole("dialog")
    expect(within(dialog).getByLabelText("Name")).toHaveFocus()
    await user.type(within(dialog).getByLabelText("Name"), "service")
    await user.type(within(dialog).getByLabelText("Origin"), profile.origin)
    await user.type(within(dialog).getByLabelText("Credential"), "new-secret")
    await user.click(within(dialog).getByRole("button", { name: "Save" }))
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument())
    expect(mockedAPI.createHTTP).toHaveBeenCalledWith({ name: "service", origin: profile.origin, auth_type: "bearer", note: "", group_id: 0, credential: "new-secret" })
    expect(resource.reload).toHaveBeenCalledOnce()
    expect(notify).toHaveBeenCalledWith('Created HTTP connection "service".', "success")
    await user.click(screen.getByRole("button", { name: "New HTTP connection" }))
    dialog = await screen.findByRole("dialog")
    expect(within(dialog).getByLabelText("Credential")).toHaveValue("")
  })

  test("edits ordinary metadata with omitted unchanged credentials", async () => {
    const { user, resource } = setup()
    mockedAPI.updateHTTP.mockResolvedValue(profile)
    await user.click(screen.getByRole("button", { name: "Edit service" }))
    const dialog = await screen.findByRole("dialog")
    await user.type(within(dialog).getByLabelText("Note"), " updated")
    await user.click(within(dialog).getByRole("button", { name: "Save" }))
    await waitFor(() => expect(mockedAPI.updateHTTP).toHaveBeenCalledWith(1, { name: "service", origin: profile.origin, auth_type: "bearer", note: "Operations updated", group_id: 3 }))
    expect(resource.reload).toHaveBeenCalledOnce()
  })

  test.each(["cancel", "escape", "close"])("clears drafts on %s and restores focus", async close => {
    const { user } = setup()
    const trigger = screen.getByRole("button", { name: "Edit service" })
    await user.click(trigger)
    let dialog = await screen.findByRole("dialog")
    await user.type(within(dialog).getByLabelText("Credential"), "discard-me")
    if (close === "escape") await user.keyboard("{Escape}")
    else await user.click(within(dialog).getByRole("button", { name: close === "cancel" ? "Cancel" : "Close" }))
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument())
    expect(trigger).toHaveFocus()
    await user.click(trigger)
    dialog = await screen.findByRole("dialog")
    expect(within(dialog).getByLabelText("Credential")).toHaveValue("")
  })

  test("retains draft and exposes submit errors, then blocks duplicate pending submit", async () => {
    const { user } = setup()
    mockedAPI.updateHTTP.mockRejectedValueOnce(new Error("name already exists"))
    await user.click(screen.getByRole("button", { name: "Edit service" }))
    const dialog = await screen.findByRole("dialog")
    await user.type(within(dialog).getByLabelText("Credential"), "rotation")
    await user.click(within(dialog).getByRole("button", { name: "Save" }))
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("name already exists")
    expect(within(dialog).getByLabelText("Credential")).toHaveValue("rotation")
    mockedAPI.updateHTTP.mockReturnValueOnce(new Promise(() => {}))
    await user.click(within(dialog).getByRole("button", { name: "Save" }))
    expect(within(dialog).getByRole("button", { name: "Saving" })).toBeDisabled()
    expect(within(dialog).getByRole("button", { name: "Cancel" })).toBeDisabled()
    await user.keyboard("{Escape}")
    expect(screen.getByRole("dialog")).toBeInTheDocument()
    expect(mockedAPI.updateHTTP).toHaveBeenCalledTimes(2)
  })

  test.each([false, true])("archives/restores archived=%s and reloads", async archived => {
    const { user, resource } = setup({ data: [{ ...profile, archived }] })
    mockedAPI.archiveHTTP.mockResolvedValue(undefined)
    await user.click(screen.getByRole("button", { name: `${archived ? "Restore" : "Archive"} service` }))
    await waitFor(() => expect(mockedAPI.archiveHTTP).toHaveBeenCalledWith(1, !archived))
    expect(resource.reload).toHaveBeenCalledOnce()
    expect(notify).toHaveBeenCalledWith(`${archived ? "Restored" : "Archived"} HTTP connection "service".`, "success")
  })

  test("confirms delete without nonexistent dependents endpoint, reports error, retries and reloads", async () => {
    const { user, resource } = setup()
    mockedAPI.deleteHTTP.mockRejectedValueOnce(new Error("delete unavailable")).mockResolvedValueOnce(undefined)
    await user.click(screen.getByRole("button", { name: "Delete service" }))
    const dialog = await screen.findByRole("dialog")
    expect(within(dialog).getByText('This will permanently delete "service" and its note.')).toBeInTheDocument()
    expect(mockedAPI.deleteHTTP).not.toHaveBeenCalled()
    await user.click(within(dialog).getByRole("button", { name: "Delete" }))
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("delete unavailable")
    await user.click(within(dialog).getByRole("button", { name: "Delete" }))
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument())
    expect(mockedAPI.deleteHTTP).toHaveBeenCalledWith(1)
    expect(resource.reload).toHaveBeenCalledOnce()
  })

  test("reports archive failures without claiming success or reloading", async () => {
    const { user, resource } = setup()
    mockedAPI.archiveHTTP.mockRejectedValue(new Error("archive unavailable"))
    await user.click(screen.getByRole("button", { name: "Archive service" }))
    await waitFor(() => expect(notify).toHaveBeenCalledWith("archive unavailable", "error"))
    expect(resource.reload).not.toHaveBeenCalled()
  })

  test("offers retry for load errors", async () => {
    const { user, resource } = setup({ error: new Error("offline") })
    expect(screen.getByRole("alert")).toHaveTextContent("Unable to load HTTP connections")
    await user.click(screen.getByRole("button", { name: "Retry" }))
    expect(resource.reload).toHaveBeenCalledOnce()
  })

  test("shows loading and empty states", () => {
    const { unmount } = render(<HTTPTab resource={{ data: [], loading: true, error: null, reload: vi.fn() }} groups={[]} notify={notify} />)
    expect(screen.getByText("Loading…")).toBeInTheDocument()
    unmount()
    setup({ data: [] })
    expect(screen.getByText("No HTTP connections yet.")).toBeInTheDocument()
  })
})
