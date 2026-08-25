import { render, screen, waitFor, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { beforeEach, describe, expect, test, vi } from "vitest"
import { api, ApiError } from "@/api/client"
import type { Group } from "@/api/types"
import type { ListResource } from "@/hooks/use-list-resource"
import { GroupsTab } from "./groups-tab"

vi.mock("@/api/client", () => {
  class MockApiError extends Error {
    code: string
    status: number
    constructor(code: string, message: string, status: number) {
      super(message)
      this.name = "ApiError"
      this.code = code
      this.status = status
    }
  }
  return {
    api: {
      createGroup: vi.fn(),
      updateGroup: vi.fn(),
      deleteGroup: vi.fn(),
      groupDependents: vi.fn(),
    },
    ApiError: MockApiError,
  }
})

const mockedAPI = vi.mocked(api)

function group(id: number, name: string, overrides: Partial<Group> = {}): Group {
  return {
    id,
    name,
    ssh_connection_count: 0,
    db_connection_count: 0,
    created_at: "2026-08-24T00:00:00Z",
    updated_at: "2026-08-24T00:00:00Z",
    ...overrides,
  }
}

function resource(overrides: Partial<ListResource<Group>> = {}): ListResource<Group> {
  return {
    data: [],
    loading: false,
    error: null,
    reload: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  }
}

const notify = vi.fn()

beforeEach(() => {
  mockedAPI.createGroup.mockReset()
  mockedAPI.updateGroup.mockReset()
  mockedAPI.deleteGroup.mockReset()
  mockedAPI.groupDependents.mockReset()
  notify.mockReset()
})

describe("GroupsTab", () => {
  test("shows a loading state while the resource loads", () => {
    render(<GroupsTab resource={resource({ loading: true })} notify={notify} />)
    expect(screen.getByText("Loading…")).toBeInTheDocument()
  })

  test("shows an empty state when no groups exist", () => {
    render(<GroupsTab resource={resource({ data: [] })} notify={notify} />)
    expect(screen.getByText("No groups yet.")).toBeInTheDocument()
  })

  test("shows a load error with a Retry action", async () => {
    const user = userEvent.setup()
    const reload = vi.fn().mockResolvedValue(undefined)
    render(<GroupsTab resource={resource({ error: new Error("boom"), reload })} notify={notify} />)

    expect(screen.getByRole("alert")).toHaveTextContent("Unable to load groups")
    await user.click(screen.getByRole("button", { name: "Retry" }))
    expect(reload).toHaveBeenCalledTimes(1)
  })

  test("renders rows with used-by counts and filters by name case-insensitively", async () => {
    const user = userEvent.setup()
    render(
      <GroupsTab
        resource={resource({
          data: [
            group(1, "prod", { ssh_connection_count: 2, db_connection_count: 1 }),
            group(2, "staging"),
          ],
        })}
        notify={notify}
      />,
    )

    expect(screen.getByText("prod")).toBeInTheDocument()
    expect(screen.getByText("SSH 2 · DB 1")).toBeInTheDocument()
    expect(screen.getByText("staging")).toBeInTheDocument()

    await user.type(screen.getByLabelText("Search groups"), "STAG")
    expect(screen.queryByText("prod")).not.toBeInTheDocument()
    expect(screen.getByText("staging")).toBeInTheDocument()
  })

  test("creates a group through the dialog, reloads, and notifies", async () => {
    const user = userEvent.setup()
    const reload = vi.fn().mockResolvedValue(undefined)
    mockedAPI.createGroup.mockResolvedValue(group(1, "prod"))
    render(<GroupsTab resource={resource({ data: [], reload })} notify={notify} />)

    await user.click(screen.getByRole("button", { name: "New group" }))
    const dialog = await screen.findByRole("dialog")
    await user.type(within(dialog).getByLabelText("Name"), "prod")
    await user.click(within(dialog).getByRole("button", { name: "Save" }))

    await waitFor(() => expect(mockedAPI.createGroup).toHaveBeenCalledTimes(1))
    expect(mockedAPI.createGroup).toHaveBeenCalledWith({ name: "prod" })
    expect(reload).toHaveBeenCalledTimes(1)
    expect(notify).toHaveBeenCalledWith('Created group "prod".', "success")
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument())
  })

  test("renames a group with the current name prefilled", async () => {
    const user = userEvent.setup()
    const reload = vi.fn().mockResolvedValue(undefined)
    mockedAPI.updateGroup.mockResolvedValue(group(1, "production"))
    render(<GroupsTab resource={resource({ data: [group(1, "prod")], reload })} notify={notify} />)

    await user.click(screen.getByRole("button", { name: "Edit prod" }))
    const dialog = await screen.findByRole("dialog")
    const nameInput = within(dialog).getByLabelText("Name")
    expect(nameInput).toHaveValue("prod")
    await user.clear(nameInput)
    await user.type(nameInput, "production")
    await user.click(within(dialog).getByRole("button", { name: "Save" }))

    await waitFor(() => expect(mockedAPI.updateGroup).toHaveBeenCalledTimes(1))
    expect(mockedAPI.updateGroup).toHaveBeenCalledWith(1, { name: "production" })
    expect(reload).toHaveBeenCalledTimes(1)
    expect(notify).toHaveBeenCalledWith('Updated group "production".', "success")
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument())
  })

  test("keeps the dialog open with the entered name after a rejected submit", async () => {
    const user = userEvent.setup()
    mockedAPI.createGroup.mockRejectedValue(
      new ApiError("conflict", "a resource with that name already exists", 409),
    )
    render(<GroupsTab resource={resource({ data: [] })} notify={notify} />)

    await user.click(screen.getByRole("button", { name: "New group" }))
    const dialog = await screen.findByRole("dialog")
    await user.type(within(dialog).getByLabelText("Name"), "dup")
    await user.click(within(dialog).getByRole("button", { name: "Save" }))

    const alert = await within(dialog).findByRole("alert")
    expect(alert).toHaveTextContent("a resource with that name already exists")
    expect(within(dialog).getByLabelText("Name")).toHaveValue("dup")
    expect(screen.getByRole("dialog")).toBeInTheDocument()
  })

  test("lists dependents in the delete confirmation and still allows deletion", async () => {
    const user = userEvent.setup()
    const reload = vi.fn().mockResolvedValue(undefined)
    mockedAPI.groupDependents.mockResolvedValue({
      ssh: [{ id: 2, name: "jump-a" }],
      db: [{ id: 3, name: "appdb" }],
    })
    mockedAPI.deleteGroup.mockResolvedValue(undefined)
    render(<GroupsTab resource={resource({ data: [group(1, "prod")], reload })} notify={notify} />)

    await user.click(screen.getByRole("button", { name: "Delete prod" }))
    const dialog = await screen.findByRole("dialog")
    expect(mockedAPI.groupDependents).toHaveBeenCalledWith(1)
    expect(await within(dialog).findByText(/jump-a/)).toBeInTheDocument()
    expect(within(dialog).getByText(/appdb/)).toBeInTheDocument()
    expect(within(dialog).getByText(/will become ungrouped/)).toBeInTheDocument()
    await user.click(within(dialog).getByRole("button", { name: "Delete" }))

    await waitFor(() => expect(mockedAPI.deleteGroup).toHaveBeenCalledWith(1))
    expect(reload).toHaveBeenCalledTimes(1)
    expect(notify).toHaveBeenCalledWith('Deleted group "prod".', "success")
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument())
  })

  test("confirms deletion with no dependents", async () => {
    const user = userEvent.setup()
    const reload = vi.fn().mockResolvedValue(undefined)
    mockedAPI.groupDependents.mockResolvedValue({ ssh: [], db: [] })
    mockedAPI.deleteGroup.mockResolvedValue(undefined)
    render(<GroupsTab resource={resource({ data: [group(1, "prod")], reload })} notify={notify} />)

    await user.click(screen.getByRole("button", { name: "Delete prod" }))
    const dialog = await screen.findByRole("dialog")
    expect(await within(dialog).findByText("No other connections reference it.")).toBeInTheDocument()
    await user.click(within(dialog).getByRole("button", { name: "Delete" }))

    await waitFor(() => expect(mockedAPI.deleteGroup).toHaveBeenCalledWith(1))
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument())
  })
})
