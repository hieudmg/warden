import { render, screen, waitFor, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { beforeEach, describe, expect, test, vi } from "vitest"
import { api, ApiError } from "@/api/client"
import type { SSHConnection } from "@/api/types"
import type { ListResource } from "@/hooks/use-list-resource"
import { SSHTab } from "./ssh-tab"

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
      createSSH: vi.fn(),
      updateSSH: vi.fn(),
      deleteSSH: vi.fn(),
      sshDependents: vi.fn(),
    },
    ApiError: MockApiError,
  }
})

const mockedAPI = vi.mocked(api)

function ssh(id: number, name: string, overrides: Partial<SSHConnection> = {}): SSHConnection {
  return {
    id,
    name,
    host: "10.0.0.1",
    port: 22,
    username: "root",
    has_password: false,
    has_private_key: false,
    has_private_key_passphrase: false,
    proxy_host: "",
    proxy_port: 0,
    proxy_username: "",
    has_proxy_password: false,
    jump_connection_ids: "[]",
    default_dir: "",
    created_at: "2026-08-24T00:00:00Z",
    updated_at: "2026-08-24T00:00:00Z",
    ...overrides,
  }
}

function resource(overrides: Partial<ListResource<SSHConnection>> = {}): ListResource<SSHConnection> {
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
  mockedAPI.createSSH.mockReset()
  mockedAPI.updateSSH.mockReset()
  mockedAPI.deleteSSH.mockReset()
  mockedAPI.sshDependents.mockReset()
  notify.mockReset()
})

describe("SSHTab", () => {
  test("shows a loading state while the resource loads", () => {
    render(<SSHTab resource={resource({ loading: true })} notify={notify} />)
    expect(screen.getByText("Loading…")).toBeInTheDocument()
  })

  test("shows an empty state when no connections exist", () => {
    render(<SSHTab resource={resource({ data: [] })} notify={notify} />)
    expect(screen.getByText("No SSH connections yet.")).toBeInTheDocument()
  })

  test("shows a load error with a Retry action", async () => {
    const user = userEvent.setup()
    const reload = vi.fn().mockResolvedValue(undefined)
    render(<SSHTab resource={resource({ error: new Error("boom"), reload })} notify={notify} />)

    expect(screen.getByRole("alert")).toHaveTextContent("Unable to load SSH connections")
    await user.click(screen.getByRole("button", { name: "Retry" }))
    expect(reload).toHaveBeenCalledTimes(1)
  })

  test("renders row columns with redacted auth badges, proxy, jump labels, and default dir", () => {
    const profiles = [ssh(2, "jump-a", { host: "10.0.0.2", username: "jump-user" })]
    const connection = ssh(1, "bastion", {
      has_password: true,
      has_private_key: true,
      has_private_key_passphrase: false,
      has_proxy_password: true,
      proxy_host: "proxy.example",
      proxy_port: 1080,
      proxy_username: "proxy-user",
      jump_connection_ids: "[2,99]",
      default_dir: "/srv",
    })
    render(<SSHTab resource={resource({ data: [connection, ...profiles] })} notify={notify} />)

    expect(screen.getByText("bastion")).toBeInTheDocument()
    expect(screen.getByText("10.0.0.1:22")).toBeInTheDocument()
    expect(screen.getByText("root")).toBeInTheDocument()
    expect(screen.getByText("Password")).toBeInTheDocument()
    expect(screen.getByText("Private key")).toBeInTheDocument()
    expect(screen.getByText("Proxy password")).toBeInTheDocument()
    expect(screen.getByText("proxy.example:1080")).toBeInTheDocument()
    expect(screen.getByText("jump-a, Missing SSH #99")).toBeInTheDocument()
    expect(screen.getByText("/srv")).toBeInTheDocument()
  })

  test("creates a connection through the dialog with a converted payload", async () => {
    const user = userEvent.setup()
    const reload = vi.fn().mockResolvedValue(undefined)
    mockedAPI.createSSH.mockResolvedValue(ssh(1, "bastion"))
    render(<SSHTab resource={resource({ data: [], reload })} notify={notify} />)

    await user.click(screen.getByRole("button", { name: "New connection" }))
    const dialog = await screen.findByRole("dialog")
    await user.type(within(dialog).getByLabelText("Name"), "bastion")
    await user.type(within(dialog).getByLabelText("Host"), "10.0.0.1")
    await user.type(within(dialog).getByLabelText("Username"), "root")
    await user.click(within(dialog).getByRole("button", { name: "Save" }))

    await waitFor(() => expect(mockedAPI.createSSH).toHaveBeenCalledTimes(1))
    expect(mockedAPI.createSSH).toHaveBeenCalledWith({
      name: "bastion",
      host: "10.0.0.1",
      port: 22,
      username: "root",
      password: null,
      private_key: null,
      private_key_passphrase: null,
      proxy_host: "",
      proxy_port: 0,
      proxy_username: "",
      proxy_password: null,
      jump_connection_ids: "[]",
      default_dir: "",
    })
    expect(reload).toHaveBeenCalledTimes(1)
    expect(notify).toHaveBeenCalledWith('Created SSH connection "bastion".', "success")
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument())
  })

  test("edits a connection with blank secrets serialized as null", async () => {
    const user = userEvent.setup()
    const reload = vi.fn().mockResolvedValue(undefined)
    mockedAPI.updateSSH.mockResolvedValue(ssh(1, "renamed"))
    render(<SSHTab resource={resource({ data: [ssh(1, "bastion")], reload })} notify={notify} />)

    await user.click(screen.getByRole("button", { name: "Edit bastion" }))
    const dialog = await screen.findByRole("dialog")
    const nameInput = within(dialog).getByLabelText("Name")
    expect(nameInput).toHaveValue("bastion")
    await user.clear(nameInput)
    await user.type(nameInput, "renamed")
    await user.click(within(dialog).getByRole("button", { name: "Save" }))

    await waitFor(() => expect(mockedAPI.updateSSH).toHaveBeenCalledTimes(1))
    expect(mockedAPI.updateSSH).toHaveBeenCalledWith(
      1,
      expect.objectContaining({
        name: "renamed",
        password: null,
        private_key: null,
        private_key_passphrase: null,
        proxy_password: null,
      }),
    )
    expect(reload).toHaveBeenCalledTimes(1)
    expect(notify).toHaveBeenCalledWith('Updated SSH connection "renamed".', "success")
  })

  test("keeps the dialog open with entered values after a rejected submit", async () => {
    const user = userEvent.setup()
    mockedAPI.createSSH.mockRejectedValue(
      new ApiError("conflict", "a connection with that name already exists", 409),
    )
    render(<SSHTab resource={resource({ data: [] })} notify={notify} />)

    await user.click(screen.getByRole("button", { name: "New connection" }))
    const dialog = await screen.findByRole("dialog")
    await user.type(within(dialog).getByLabelText("Name"), "dup")
    await user.type(within(dialog).getByLabelText("Host"), "10.0.0.9")
    await user.type(within(dialog).getByLabelText("Username"), "root")
    await user.click(within(dialog).getByRole("button", { name: "Save" }))

    const alert = await within(dialog).findByRole("alert")
    expect(alert).toHaveTextContent("a connection with that name already exists")
    expect(within(dialog).getByLabelText("Name")).toHaveValue("dup")
    expect(within(dialog).getByLabelText("Host")).toHaveValue("10.0.0.9")
    expect(screen.getByRole("dialog")).toBeInTheDocument()
  })

  test("blocks duplicate submit while a request is pending", async () => {
    const user = userEvent.setup()
    mockedAPI.createSSH.mockReturnValue(new Promise(() => {}))
    render(<SSHTab resource={resource({ data: [] })} notify={notify} />)

    await user.click(screen.getByRole("button", { name: "New connection" }))
    const dialog = await screen.findByRole("dialog")
    await user.type(within(dialog).getByLabelText("Name"), "slow")
    await user.type(within(dialog).getByLabelText("Host"), "10.0.0.1")
    await user.type(within(dialog).getByLabelText("Username"), "root")
    await user.click(within(dialog).getByRole("button", { name: "Save" }))

    expect(mockedAPI.createSSH).toHaveBeenCalledTimes(1)
    const saving = within(dialog).getByRole("button", { name: "Saving" })
    expect(saving).toBeDisabled()
    await user.click(saving)
    expect(mockedAPI.createSSH).toHaveBeenCalledTimes(1)
  })

  test("looks up dependents before opening the delete confirmation", async () => {
    const user = userEvent.setup()
    mockedAPI.sshDependents.mockResolvedValue({
      ssh: [{ id: 2, name: "jump-a" }],
      db: [{ id: 3, name: "db-1" }],
    })
    render(<SSHTab resource={resource({ data: [ssh(1, "bastion")] })} notify={notify} />)

    await user.click(screen.getByRole("button", { name: "Delete bastion" }))
    const dialog = await screen.findByRole("dialog")
    expect(mockedAPI.sshDependents).toHaveBeenCalledWith(1)
    expect(await within(dialog).findByText(/jump-a/)).toBeInTheDocument()
    expect(within(dialog).getByText(/db-1/)).toBeInTheDocument()
    expect(within(dialog).getByText(/will become invalid/)).toBeInTheDocument()
  })

  test("deletes after confirmation, refreshes, and notifies", async () => {
    const user = userEvent.setup()
    const reload = vi.fn().mockResolvedValue(undefined)
    mockedAPI.sshDependents.mockResolvedValue({ ssh: [], db: [] })
    mockedAPI.deleteSSH.mockResolvedValue(undefined)
    render(<SSHTab resource={resource({ data: [ssh(1, "bastion")], reload })} notify={notify} />)

    await user.click(screen.getByRole("button", { name: "Delete bastion" }))
    const dialog = await screen.findByRole("dialog")
    expect(await within(dialog).findByText("No other connections reference it.")).toBeInTheDocument()
    await user.click(within(dialog).getByRole("button", { name: "Delete" }))

    await waitFor(() => expect(mockedAPI.deleteSSH).toHaveBeenCalledWith(1))
    expect(reload).toHaveBeenCalledTimes(1)
    expect(notify).toHaveBeenCalledWith('Deleted SSH connection "bastion".', "success")
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument())
  })

  test("withholds Delete when the dependents lookup fails", async () => {
    const user = userEvent.setup()
    mockedAPI.sshDependents.mockRejectedValue(new Error("dependents unavailable"))
    render(<SSHTab resource={resource({ data: [ssh(1, "bastion")] })} notify={notify} />)

    await user.click(screen.getByRole("button", { name: "Delete bastion" }))
    const dialog = await screen.findByRole("dialog")
    expect(mockedAPI.sshDependents).toHaveBeenCalledWith(1)
    expect(await within(dialog).findByText("Unable to check for dependents.")).toBeInTheDocument()
    expect(within(dialog).queryByRole("button", { name: "Delete" })).not.toBeInTheDocument()
    expect(within(dialog).getByRole("button", { name: "Cancel" })).toBeInTheDocument()
  })

  test("focuses the first meaningful control when the create dialog opens", async () => {
    const user = userEvent.setup()
    render(<SSHTab resource={resource({ data: [] })} notify={notify} />)

    await user.click(screen.getByRole("button", { name: "New connection" }))
    const dialog = await screen.findByRole("dialog")
    expect(within(dialog).getByLabelText("Name")).toHaveFocus()
  })

  test("closes the dialog on Escape and returns focus to the trigger", async () => {
    const user = userEvent.setup()
    render(<SSHTab resource={resource({ data: [] })} notify={notify} />)

    const trigger = screen.getByRole("button", { name: "New connection" })
    await user.click(trigger)
    const dialog = await screen.findByRole("dialog")
    expect(within(dialog).getByLabelText("Name")).toHaveFocus()

    await user.keyboard("{Escape}")
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument())
    expect(trigger).toHaveFocus()
  })

  test("names the target connection in the delete confirmation", async () => {
    const user = userEvent.setup()
    mockedAPI.sshDependents.mockResolvedValue({ ssh: [], db: [] })
    render(<SSHTab resource={resource({ data: [ssh(1, "bastion")] })} notify={notify} />)

    await user.click(screen.getByRole("button", { name: "Delete bastion" }))
    const dialog = await screen.findByRole("dialog")
    expect(
      await within(dialog).findByText('This will permanently delete "bastion".'),
    ).toBeInTheDocument()
  })

  test("shows Deleting and disables the button while the delete request is pending", async () => {
    const user = userEvent.setup()
    mockedAPI.sshDependents.mockResolvedValue({ ssh: [], db: [] })
    mockedAPI.deleteSSH.mockReturnValue(new Promise(() => {}))
    render(<SSHTab resource={resource({ data: [ssh(1, "bastion")] })} notify={notify} />)

    await user.click(screen.getByRole("button", { name: "Delete bastion" }))
    const dialog = await screen.findByRole("dialog")
    await user.click(within(dialog).getByRole("button", { name: "Delete" }))

    expect(mockedAPI.deleteSSH).toHaveBeenCalledTimes(1)
    const deleting = within(dialog).getByRole("button", { name: "Deleting" })
    expect(deleting).toBeDisabled()
  })

  test("never renders secret values, only presence badges", () => {
    render(
      <SSHTab
        resource={resource({
          data: [ssh(1, "bastion", { has_password: true, has_private_key: true })],
        })}
        notify={notify}
      />,
    )
    expect(screen.getByText("Password")).toBeInTheDocument()
    expect(screen.getByText("Private key")).toBeInTheDocument()
    expect(screen.queryByText("hunter2")).not.toBeInTheDocument()
    expect(screen.queryByText("secret-key")).not.toBeInTheDocument()
  })
})
