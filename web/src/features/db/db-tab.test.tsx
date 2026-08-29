import { render, screen, waitFor, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { beforeEach, describe, expect, test, vi } from "vitest"
import { api, ApiError } from "@/api/client"
import type { DBConnection, SSHConnection } from "@/api/types"
import type { ListResource } from "@/hooks/use-list-resource"
import { DBTab } from "./db-tab"

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
      createDB: vi.fn(),
      updateDB: vi.fn(),
      deleteDB: vi.fn(),
      dbDependents: vi.fn(),
    },
    ApiError: MockApiError,
  }
})

const mockedAPI = vi.mocked(api)

function db(id: number, name: string, overrides: Partial<DBConnection> = {}): DBConnection {
  const connection = {
    id,
    name,
    host: "127.0.0.1",
    port: 3306,
    username: "app",
    has_password: false,
    database: "warden",
    databases: [{ name: "warden", is_default: true }],
    ssh_connection_id: 0,
    group_id: 0,
    created_at: "2026-08-24T00:00:00Z",
    updated_at: "2026-08-24T00:00:00Z",
    ...overrides,
  }
  if (!("databases" in overrides)) {
    connection.databases = [{ name: connection.database, is_default: true }]
  }
  return connection
}

function ssh(id: number, name: string): SSHConnection {
  return {
    id,
    name,
    host: "10.0.0.1",
    port: 22,
    username: "root",
    has_password: false,
    key_pair_id: 0,
    proxy_host: "",
    proxy_port: 0,
    proxy_username: "",
    has_proxy_password: false,
    jump_connection_ids: "[]",
    default_dir: "",
    group_id: 0,
    created_at: "2026-08-24T00:00:00Z",
    updated_at: "2026-08-24T00:00:00Z",
  }
}

function resource(overrides: Partial<ListResource<DBConnection>> = {}): ListResource<DBConnection> {
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
  mockedAPI.createDB.mockReset()
  mockedAPI.updateDB.mockReset()
  mockedAPI.deleteDB.mockReset()
  mockedAPI.dbDependents.mockReset()
  notify.mockReset()
})

describe("DBTab", () => {
  test("shows a loading state while the resource loads", () => {
    render(<DBTab resource={resource({ loading: true })} sshProfiles={[]} groups={[]} notify={notify} />)
    expect(screen.getByText("Loading…")).toBeInTheDocument()
  })

  test("shows an empty state when no connections exist", () => {
    render(<DBTab resource={resource({ data: [] })} sshProfiles={[]} groups={[]} notify={notify} />)
    expect(screen.getByText("No database connections yet.")).toBeInTheDocument()
  })

  test("shows a load error with a Retry action", async () => {
    const user = userEvent.setup()
    const reload = vi.fn().mockResolvedValue(undefined)
    render(
      <DBTab
        resource={resource({ error: new Error("boom"), reload })}
        sshProfiles={[]}
        groups={[]} notify={notify}
      />,
    )

    expect(screen.getByRole("alert")).toHaveTextContent("Unable to load database connections")
    await user.click(screen.getByRole("button", { name: "Retry" }))
    expect(reload).toHaveBeenCalledTimes(1)
  })

  test("renders every database and marks the default", () => {
    const connection = db(1, "db-1", {
      database: "main",
      databases: [
        { name: "main", is_default: true },
        { name: "audit", is_default: false },
      ],
    })
    render(<DBTab resource={resource({ data: [connection] })} sshProfiles={[]} groups={[]} notify={notify} />)

    const row = screen.getAllByRole("row")[1]
    expect(within(row).getByText("main")).toBeInTheDocument()
    expect(within(row).getByText("audit")).toBeInTheDocument()
    expect(within(row).getByText("Default")).toBeInTheDocument()
  })

  test("renders row columns with Direct, named, and missing SSH values", () => {
    const profiles = [ssh(2, "jump-a")]
    const connections = [
      db(1, "db-1", { host: "127.0.0.1", has_password: true, username: "app", database: "warden" }),
      db(2, "db-2", { host: "127.0.0.2", username: "reader", database: "analytics", ssh_connection_id: 2 }),
      db(3, "db-3", { host: "127.0.0.3", username: "admin", database: "logs", ssh_connection_id: 91 }),
    ]
    render(<DBTab resource={resource({ data: connections })} sshProfiles={profiles} groups={[]} notify={notify} />)

    expect(screen.getByText("db-1")).toBeInTheDocument()
    expect(screen.getByText("127.0.0.1:3306")).toBeInTheDocument()
    expect(screen.getByText("app")).toBeInTheDocument()
    expect(screen.getByText("Password")).toBeInTheDocument()
    expect(screen.getByText("warden")).toBeInTheDocument()
    expect(screen.getByText("Direct")).toBeInTheDocument()
    expect(screen.getByText("jump-a")).toBeInTheDocument()
    expect(screen.getByText("Missing SSH #91")).toBeInTheDocument()
  })

  test("puts group first, sorts grouped rows, and cycles group colors", () => {
    const connections = [
      db(1, "zulu", { group_id: 2, group_name: "beta" }),
      db(2, "bravo", { group_id: 1, group_name: "alpha" }),
      db(3, "alpha", { group_id: 1, group_name: "alpha" }),
      db(4, "ungrouped", { group_id: 0 }),
      db(5, "missing", { group_id: 8 }),
    ]
    render(<DBTab resource={resource({ data: connections })} sshProfiles={[]} groups={[]} notify={notify} />)

    const rows = screen.getAllByRole("row")
    expect(within(rows[0]).getAllByRole("columnheader")[0]).toHaveTextContent("Group")
    expect(rows.slice(1).map(row => within(row).getAllByRole("cell")[1].textContent)).toEqual([
      "alpha",
      "bravo",
      "zulu",
      "missing",
      "ungrouped",
    ])
    expect(rows.slice(1).map(row => within(row).getAllByRole("cell")[0].textContent)).toEqual([
      "alpha",
      "alpha",
      "beta",
      "Missing group #8",
      "(Ungrouped)",
    ])
    expect(rows[1]).toHaveClass("bg-red-100")
    expect(rows[2]).toHaveClass("bg-red-100")
    expect(rows[3]).toHaveClass("bg-orange-100")
    expect(rows[4]).toHaveClass("bg-amber-100")
    expect(rows[5]).toHaveClass("bg-gray-100")
  })

  test("renders the group column with named, ungrouped, and missing values", () => {
    const connections = [
      db(1, "db-1", { group_id: 3, group_name: "prod" }),
      db(2, "db-2", { group_id: 0 }),
      db(3, "db-3", { group_id: 7 }),
    ]
    render(<DBTab resource={resource({ data: connections })} sshProfiles={[]} groups={[]} notify={notify} />)

    expect(screen.getByText("prod")).toBeInTheDocument()
    expect(screen.getByText("(Ungrouped)")).toBeInTheDocument()
    expect(screen.getByText("Missing group #7")).toBeInTheDocument()
  })

  test("creates a connection through the dialog with a converted payload", async () => {
    const user = userEvent.setup()
    const reload = vi.fn().mockResolvedValue(undefined)
    mockedAPI.createDB.mockResolvedValue(db(1, "db-1"))
    render(<DBTab resource={resource({ data: [], reload })} sshProfiles={[]} groups={[]} notify={notify} />)

    await user.click(screen.getByRole("button", { name: "New database" }))
    const dialog = await screen.findByRole("dialog")
    await user.type(within(dialog).getByLabelText("Name"), "db-1")
    await user.type(within(dialog).getByLabelText("Host"), "127.0.0.1")
    await user.type(within(dialog).getByLabelText("Username"), "app")
    await user.type(within(dialog).getByLabelText("Database name"), "warden")
    await user.click(within(dialog).getByRole("button", { name: "Save" }))

    await waitFor(() => expect(mockedAPI.createDB).toHaveBeenCalledTimes(1))
    expect(mockedAPI.createDB).toHaveBeenCalledWith({
      name: "db-1",
      host: "127.0.0.1",
      port: 3306,
      username: "app",
      password: null,
      database: "warden",
      databases: [{ name: "warden", is_default: true }],
      ssh_connection_id: 0,
      group_id: 0,
    })
    expect(reload).toHaveBeenCalledTimes(1)
    expect(notify).toHaveBeenCalledWith('Created database connection "db-1".', "success")
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument())
  })

  test("edits a connection with a blank password serialized as null", async () => {
    const user = userEvent.setup()
    const reload = vi.fn().mockResolvedValue(undefined)
    mockedAPI.updateDB.mockResolvedValue(db(1, "renamed"))
    render(<DBTab resource={resource({ data: [db(1, "db-1")], reload })} sshProfiles={[]} groups={[]} notify={notify} />)

    await user.click(screen.getByRole("button", { name: "Edit db-1" }))
    const dialog = await screen.findByRole("dialog")
    const nameInput = within(dialog).getByLabelText("Name")
    expect(nameInput).toHaveValue("db-1")
    await user.clear(nameInput)
    await user.type(nameInput, "renamed")
    await user.click(within(dialog).getByRole("button", { name: "Save" }))

    await waitFor(() => expect(mockedAPI.updateDB).toHaveBeenCalledTimes(1))
    expect(mockedAPI.updateDB).toHaveBeenCalledWith(
      1,
      expect.objectContaining({
        name: "renamed",
        password: null,
        ssh_connection_id: 0,
      }),
    )
    expect(reload).toHaveBeenCalledTimes(1)
    expect(notify).toHaveBeenCalledWith('Updated database connection "renamed".', "success")
  })

  test("keeps the dialog open with entered values after a rejected submit", async () => {
    const user = userEvent.setup()
    mockedAPI.createDB.mockRejectedValue(
      new ApiError("conflict", "a connection with that name already exists", 409),
    )
    render(<DBTab resource={resource({ data: [] })} sshProfiles={[]} groups={[]} notify={notify} />)

    await user.click(screen.getByRole("button", { name: "New database" }))
    const dialog = await screen.findByRole("dialog")
    await user.type(within(dialog).getByLabelText("Name"), "dup")
    await user.type(within(dialog).getByLabelText("Host"), "127.0.0.9")
    await user.type(within(dialog).getByLabelText("Username"), "app")
    await user.type(within(dialog).getByLabelText("Database name"), "warden")
    await user.click(within(dialog).getByRole("button", { name: "Save" }))

    const alert = await within(dialog).findByRole("alert")
    expect(alert).toHaveTextContent("a connection with that name already exists")
    expect(within(dialog).getByLabelText("Name")).toHaveValue("dup")
    expect(within(dialog).getByLabelText("Host")).toHaveValue("127.0.0.9")
    expect(screen.getByRole("dialog")).toBeInTheDocument()
  })

  test("blocks duplicate submit while a request is pending", async () => {
    const user = userEvent.setup()
    mockedAPI.createDB.mockReturnValue(new Promise(() => {}))
    render(<DBTab resource={resource({ data: [] })} sshProfiles={[]} groups={[]} notify={notify} />)

    await user.click(screen.getByRole("button", { name: "New database" }))
    const dialog = await screen.findByRole("dialog")
    await user.type(within(dialog).getByLabelText("Name"), "slow")
    await user.type(within(dialog).getByLabelText("Host"), "127.0.0.1")
    await user.type(within(dialog).getByLabelText("Username"), "app")
    await user.type(within(dialog).getByLabelText("Database name"), "warden")
    await user.click(within(dialog).getByRole("button", { name: "Save" }))

    expect(mockedAPI.createDB).toHaveBeenCalledTimes(1)
    const saving = within(dialog).getByRole("button", { name: "Saving" })
    expect(saving).toBeDisabled()
    await user.click(saving)
    expect(mockedAPI.createDB).toHaveBeenCalledTimes(1)
  })

  test("looks up dependents before opening the delete confirmation", async () => {
    const user = userEvent.setup()
    mockedAPI.dbDependents.mockResolvedValue({
      ssh: [{ id: 2, name: "jump-a" }],
      db: [{ id: 3, name: "db-2" }],
    })
    render(<DBTab resource={resource({ data: [db(1, "db-1")] })} sshProfiles={[]} groups={[]} notify={notify} />)

    await user.click(screen.getByRole("button", { name: "Delete db-1" }))
    const dialog = await screen.findByRole("dialog")
    expect(mockedAPI.dbDependents).toHaveBeenCalledWith(1)
    expect(await within(dialog).findByText(/jump-a/)).toBeInTheDocument()
    expect(within(dialog).getByText(/db-2/)).toBeInTheDocument()
    expect(within(dialog).getByText(/will become invalid/)).toBeInTheDocument()
  })

  test("deletes after confirmation, refreshes, and notifies", async () => {
    const user = userEvent.setup()
    const reload = vi.fn().mockResolvedValue(undefined)
    mockedAPI.dbDependents.mockResolvedValue({ ssh: [], db: [] })
    mockedAPI.deleteDB.mockResolvedValue(undefined)
    render(<DBTab resource={resource({ data: [db(1, "db-1")], reload })} sshProfiles={[]} groups={[]} notify={notify} />)

    await user.click(screen.getByRole("button", { name: "Delete db-1" }))
    const dialog = await screen.findByRole("dialog")
    expect(await within(dialog).findByText("No other connections reference it.")).toBeInTheDocument()
    await user.click(within(dialog).getByRole("button", { name: "Delete" }))

    await waitFor(() => expect(mockedAPI.deleteDB).toHaveBeenCalledWith(1))
    expect(reload).toHaveBeenCalledTimes(1)
    expect(notify).toHaveBeenCalledWith('Deleted database connection "db-1".', "success")
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument())
  })

  test("withholds Delete when the dependents lookup fails", async () => {
    const user = userEvent.setup()
    mockedAPI.dbDependents.mockRejectedValue(new Error("dependents unavailable"))
    render(<DBTab resource={resource({ data: [db(1, "db-1")] })} sshProfiles={[]} groups={[]} notify={notify} />)

    await user.click(screen.getByRole("button", { name: "Delete db-1" }))
    const dialog = await screen.findByRole("dialog")
    expect(mockedAPI.dbDependents).toHaveBeenCalledWith(1)
    expect(await within(dialog).findByText("Unable to check for dependents.")).toBeInTheDocument()
    expect(within(dialog).queryByRole("button", { name: "Delete" })).not.toBeInTheDocument()
    expect(within(dialog).getByRole("button", { name: "Cancel" })).toBeInTheDocument()
  })

  test("focuses the first meaningful control when the create dialog opens", async () => {
    const user = userEvent.setup()
    render(<DBTab resource={resource({ data: [] })} sshProfiles={[]} groups={[]} notify={notify} />)

    await user.click(screen.getByRole("button", { name: "New database" }))
    const dialog = await screen.findByRole("dialog")
    expect(within(dialog).getByLabelText("Name")).toHaveFocus()
  })

  test("closes the dialog on Escape and returns focus to the trigger", async () => {
    const user = userEvent.setup()
    render(<DBTab resource={resource({ data: [] })} sshProfiles={[]} groups={[]} notify={notify} />)

    const trigger = screen.getByRole("button", { name: "New database" })
    await user.click(trigger)
    const dialog = await screen.findByRole("dialog")
    expect(within(dialog).getByLabelText("Name")).toHaveFocus()

    await user.keyboard("{Escape}")
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument())
    expect(trigger).toHaveFocus()
  })

  test("names the target connection in the delete confirmation", async () => {
    const user = userEvent.setup()
    mockedAPI.dbDependents.mockResolvedValue({ ssh: [], db: [] })
    render(<DBTab resource={resource({ data: [db(1, "db-1")] })} sshProfiles={[]} groups={[]} notify={notify} />)

    await user.click(screen.getByRole("button", { name: "Delete db-1" }))
    const dialog = await screen.findByRole("dialog")
    expect(
      await within(dialog).findByText('This will permanently delete "db-1".'),
    ).toBeInTheDocument()
  })

  test("shows Deleting and disables the button while the delete request is pending", async () => {
    const user = userEvent.setup()
    mockedAPI.dbDependents.mockResolvedValue({ ssh: [], db: [] })
    mockedAPI.deleteDB.mockReturnValue(new Promise(() => {}))
    render(<DBTab resource={resource({ data: [db(1, "db-1")] })} sshProfiles={[]} groups={[]} notify={notify} />)

    await user.click(screen.getByRole("button", { name: "Delete db-1" }))
    const dialog = await screen.findByRole("dialog")
    await user.click(within(dialog).getByRole("button", { name: "Delete" }))

    expect(mockedAPI.deleteDB).toHaveBeenCalledTimes(1)
    const deleting = within(dialog).getByRole("button", { name: "Deleting" })
    expect(deleting).toBeDisabled()
  })

  test("never renders secret values, only presence badges", () => {
    render(
      <DBTab
        resource={resource({ data: [db(1, "db-1", { has_password: true })] })}
        sshProfiles={[]}
        groups={[]} notify={notify}
      />,
    )
    expect(screen.getByText("Password")).toBeInTheDocument()
    expect(screen.queryByText("hunter2")).not.toBeInTheDocument()
  })
})
