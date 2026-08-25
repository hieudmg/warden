import { render, screen, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { describe, expect, test, vi } from "vitest"
import type { DBConnection, Group, SSHConnection } from "@/api/types"
import { dbFormFromConnection, emptyDBForm, toDBRequest, type DBFormState } from "./db-form"
import { DBForm } from "./db-form"

function group(id: number, name: string): Group {
  return {
    id,
    name,
    ssh_connection_count: 0,
    db_connection_count: 0,
    created_at: "2026-08-24T00:00:00Z",
    updated_at: "2026-08-24T00:00:00Z",
  }
}

function db(id: number, name: string, overrides: Partial<DBConnection> = {}): DBConnection {
  return {
    id,
    name,
    host: "127.0.0.1",
    port: 3306,
    username: "app",
    has_password: true,
    database: "warden",
    ssh_connection_id: 0,
    group_id: 0,
    created_at: "2026-08-24T00:00:00Z",
    updated_at: "2026-08-24T00:00:00Z",
    ...overrides,
  }
}

function ssh(id: number, name: string): SSHConnection {
  return {
    id,
    name,
    host: `${name}.example`,
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
    group_id: 0,
    created_at: "2026-08-24T00:00:00Z",
    updated_at: "2026-08-24T00:00:00Z",
  }
}

describe("emptyDBForm", () => {
  test("defaults to Direct with a blank password and port 3306", () => {
    const form = emptyDBForm()
    expect(form.port).toBe("3306")
    expect(form.sshConnectionID).toBe("0")
    expect(form.password).toBe("")
    expect(form.name).toBe("")
    expect(form.host).toBe("")
    expect(form.username).toBe("")
    expect(form.database).toBe("")
    expect(form.groupID).toBe("0")
  })
})

describe("dbFormFromConnection", () => {
  test("keeps non-secret values and stringifies the SSH ID", () => {
    const form = dbFormFromConnection(db(1, "db-1", { ssh_connection_id: 91 }))
    expect(form.name).toBe("db-1")
    expect(form.host).toBe("127.0.0.1")
    expect(form.port).toBe("3306")
    expect(form.username).toBe("app")
    expect(form.database).toBe("warden")
    expect(form.sshConnectionID).toBe("91")
  })

  test("maps the saved group id to a string value", () => {
    expect(dbFormFromConnection(db(1, "db-1", { group_id: 91 })).groupID).toBe("91")
  })

  test("initializes the password blank because responses are redacted", () => {
    expect(dbFormFromConnection(db(1, "db-1")).password).toBe("")
  })
})

describe("toDBRequest", () => {
  test("serializes a blank password as null, never an empty string", () => {
    const form: DBFormState = {
      ...emptyDBForm(),
      name: "db-1",
      host: "127.0.0.1",
      username: "app",
      password: "",
      database: "warden",
    }
    expect(toDBRequest(form)).toEqual({
      name: "db-1",
      host: "127.0.0.1",
      port: 3306,
      username: "app",
      password: null,
      database: "warden",
      ssh_connection_id: 0,
      group_id: 0,
    })
  })

  test("preserves a nonblank password verbatim", () => {
    const form: DBFormState = { ...emptyDBForm(), password: "hunter2" }
    expect(toDBRequest(form).password).toBe("hunter2")
  })

  test("maps Direct to ssh_connection_id 0", () => {
    const form: DBFormState = { ...emptyDBForm(), sshConnectionID: "0" }
    expect(toDBRequest(form).ssh_connection_id).toBe(0)
  })

  test("maps a selected profile to its numeric ID", () => {
    const form: DBFormState = { ...emptyDBForm(), sshConnectionID: "5" }
    expect(toDBRequest(form).ssh_connection_id).toBe(5)
  })

  test("preserves a missing saved ID", () => {
    const form: DBFormState = { ...emptyDBForm(), sshConnectionID: "91" }
    expect(toDBRequest(form).ssh_connection_id).toBe(91)
  })

  test("maps the group value to a numeric group_id", () => {
    expect(toDBRequest({ ...emptyDBForm(), groupID: "7" }).group_id).toBe(7)
    expect(toDBRequest({ ...emptyDBForm(), groupID: "0" }).group_id).toBe(0)
  })

  test("converts numeric inputs to numbers", () => {
    const form: DBFormState = { ...emptyDBForm(), port: "3306" }
    expect(toDBRequest(form).port).toBe(3306)
  })
})

describe("DBForm", () => {
  function renderForm(overrides: Partial<Parameters<typeof DBForm>[0]> = {}) {
    const onSubmit = vi.fn()
    const onCancel = vi.fn()
    render(
      <DBForm
        connection={null}
        sshProfiles={[]}
        groups={[]}
        pending={false}
        error={null}
        onSubmit={onSubmit}
        onCancel={onCancel}
        {...overrides}
      />,
    )
    return { onSubmit, onCancel }
  }

  test("shows Missing SSH #91 for a saved missing ID and preserves it on submit", async () => {
    const user = userEvent.setup()
    const { onSubmit } = renderForm({ connection: db(1, "db-1", { ssh_connection_id: 91 }) })

    expect(screen.getByRole("combobox", { name: "SSH connection" })).toHaveTextContent(
      "Missing SSH #91",
    )
    await user.click(screen.getByRole("button", { name: "Save" }))
    expect(onSubmit).toHaveBeenCalledWith(expect.objectContaining({ ssh_connection_id: 91 }))
  })

  test("choosing Direct replaces a missing ID with 0", async () => {
    const user = userEvent.setup()
    const { onSubmit } = renderForm({ connection: db(1, "db-1", { ssh_connection_id: 91 }) })

    await user.click(screen.getByRole("combobox", { name: "SSH connection" }))
    await user.click(await screen.findByRole("option", { name: "Direct" }))
    await user.click(screen.getByRole("button", { name: "Save" }))
    expect(onSubmit).toHaveBeenCalledWith(expect.objectContaining({ ssh_connection_id: 0 }))
  })

  test("lists existing profiles as name — host:port", async () => {
    const user = userEvent.setup()
    renderForm({ sshProfiles: [ssh(2, "jump-a"), ssh(3, "db-jump")] })

    await user.click(screen.getByRole("combobox", { name: "SSH connection" }))
    expect(await screen.findByRole("option", { name: "jump-a — jump-a.example:22" })).toBeInTheDocument()
    expect(screen.getByRole("option", { name: "db-jump — db-jump.example:22" })).toBeInTheDocument()
  })

  test("filters SSH profiles by search text", async () => {
    const user = userEvent.setup()
    renderForm({ sshProfiles: [ssh(2, "jump-a"), ssh(3, "db-jump")] })

    await user.click(screen.getByRole("combobox", { name: "SSH connection" }))
    await user.type(await screen.findByPlaceholderText("Search SSH connections"), "db-jump")

    expect(screen.getByRole("option", { name: "db-jump — db-jump.example:22" })).toBeInTheDocument()
    expect(screen.queryByRole("option", { name: "jump-a — jump-a.example:22" })).not.toBeInTheDocument()
  })

  test("keeps Direct plus a Missing option when SSH profiles are unavailable", async () => {
    const user = userEvent.setup()
    renderForm({ connection: db(1, "db-1", { ssh_connection_id: 91 }), sshProfiles: [] })

    await user.click(screen.getByRole("combobox", { name: "SSH connection" }))
    expect(await screen.findByRole("option", { name: "Direct" })).toBeInTheDocument()
    expect(screen.getByRole("option", { name: "Missing SSH #91" })).toBeInTheDocument()
  })

  test("selecting an existing profile maps to its numeric ID", async () => {
    const user = userEvent.setup()
    const { onSubmit } = renderForm({ sshProfiles: [ssh(2, "jump-a")] })

    await user.type(screen.getByLabelText("Name"), "db-1")
    await user.type(screen.getByLabelText("Host"), "127.0.0.1")
    await user.type(screen.getByLabelText("Username"), "app")
    await user.type(screen.getByLabelText("Database"), "warden")
    await user.click(screen.getByRole("combobox", { name: "SSH connection" }))
    await user.click(await screen.findByRole("option", { name: "jump-a — jump-a.example:22" }))
    await user.click(screen.getByRole("button", { name: "Save" }))
    expect(onSubmit).toHaveBeenCalledWith(expect.objectContaining({ ssh_connection_id: 2 }))
  })

  test("shows Missing group #91 when the saved group is absent from the list", () => {
    renderForm({ connection: db(1, "db-1", { group_id: 91 }), groups: [] })

    const combobox = screen.getByRole("combobox", { name: "Group" })
    expect(combobox).toHaveTextContent("Missing group #91")
  })

  test("selecting a group sends its numeric group_id", async () => {
    const user = userEvent.setup()
    const onSubmit = vi.fn()
    renderForm({ groups: [group(3, "prod")], onSubmit })

    await user.type(screen.getByLabelText("Name"), "db-1")
    await user.type(screen.getByLabelText("Host"), "127.0.0.1")
    await user.type(screen.getByLabelText("Username"), "app")
    await user.type(screen.getByLabelText("Database"), "warden")
    await user.click(screen.getByRole("combobox", { name: "Group" }))
    await user.click(await screen.findByRole("option", { name: "prod" }))
    await user.click(screen.getByRole("button", { name: "Save" }))
    expect(onSubmit).toHaveBeenCalledWith(expect.objectContaining({ group_id: 3 }))
  })

  test("renders username @ host : port as one inline address row", () => {
    render(
      <DBForm
        connection={null}
        sshProfiles={[]}
        groups={[]}
        pending={false}
        error={null}
        onSubmit={vi.fn()}
        onCancel={vi.fn()}
      />,
    )
    const username = screen.getByLabelText("Username")
    const host = screen.getByLabelText("Host")
    const port = screen.getByLabelText("Port")

    const row = username.closest("div.flex.items-end.gap-2")
    expect(row).not.toBeNull()
    expect(host.closest("div.flex.items-end.gap-2")).toBe(row)
    expect(port.closest("div.flex.items-end.gap-2")).toBe(row)
    expect(within(row as HTMLElement).getByText("@")).toBeInTheDocument()
    expect(within(row as HTMLElement).getByText(":")).toBeInTheDocument()
  })

  test("renders form errors with role alert", () => {
    render(
      <DBForm
        connection={null}
        sshProfiles={[]}
        groups={[]}
        pending={false}
        error="a connection with that name already exists"
        onSubmit={vi.fn()}
        onCancel={vi.fn()}
      />,
    )
    const alert = screen.getByRole("alert")
    expect(alert).toHaveTextContent("a connection with that name already exists")
  })

  test("uses plain text inputs for credentials and disables browser autoComplete", () => {
    renderForm()
    const form = screen.getByRole("button", { name: "Save" }).closest("form")
    expect(form).not.toBeNull()
    expect(form!.getAttribute("autocomplete")).toBe("off")
    expect(document.getElementById("db-password")!.getAttribute("type")).toBeNull()
  })
})