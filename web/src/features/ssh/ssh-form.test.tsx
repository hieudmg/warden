import { render, screen, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { describe, expect, test, vi } from "vitest"
import type { Group, KeyPairSummary, SSHConnection } from "@/api/types"
import { emptySSHForm, sshFormFromConnection, toSSHRequest, type SSHFormState } from "./ssh-form"
import { SSHForm } from "./ssh-form"

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

function keyPair(id: number, name: string, overrides: Partial<KeyPairSummary> = {}): KeyPairSummary {
  return {
    id,
    name,
    has_public_key: true,
    has_private_key: true,
    has_private_key_passphrase: false,
    created_at: "2026-08-26T00:00:00Z",
    updated_at: "2026-08-26T00:00:00Z",
    ...overrides,
  }
}

function connection(overrides: Partial<SSHConnection> = {}): SSHConnection {
  return {
    id: 1,
    name: "bastion",
    host: "10.0.0.1",
    port: 22,
    username: "root",
    has_password: true,
    key_pair_id: 7,
    key_pair_name: "prod",
    proxy_host: "proxy.example",
    proxy_port: 1080,
    proxy_username: "proxy-user",
    has_proxy_password: true,
    jump_connection_ids: "[2,7,2,0,-4,99]",
    default_dir: "/srv",
    group_id: 0,
    created_at: "2026-08-24T00:00:00Z",
    updated_at: "2026-08-24T00:00:00Z",
    ...overrides,
  }
}

describe("emptySSHForm", () => {
  test("defaults to password auth with ports 22 and 1080, an empty route, and blank secrets", () => {
    const form = emptySSHForm()
    expect(form.authMode).toBe("password")
    expect(form.port).toBe("22")
    expect(form.proxyPort).toBe("1080")
    expect(form.jumpIDs).toEqual([])
    expect(form.password).toBe("")
    expect(form.keyPairID).toBe("0")
    expect(form.proxyPassword).toBe("")
    expect(form.groupID).toBe("0")
  })
})

describe("sshFormFromConnection", () => {
  test("keeps non-secret values and parses stored jump IDs", () => {
    const form = sshFormFromConnection(connection())
    expect(form.name).toBe("bastion")
    expect(form.host).toBe("10.0.0.1")
    expect(form.port).toBe("22")
    expect(form.username).toBe("root")
    expect(form.proxyHost).toBe("proxy.example")
    expect(form.proxyPort).toBe("1080")
    expect(form.proxyUsername).toBe("proxy-user")
    expect(form.defaultDir).toBe("/srv")
    expect(form.jumpIDs).toEqual([2, 7, 2, 0, -4, 99])
  })

  test("initializes every secret blank because responses are redacted", () => {
    const form = sshFormFromConnection(connection())
    expect(form.password).toBe("")
    expect(form.proxyPassword).toBe("")
  })

  test("maps the saved group id to a string value", () => {
    expect(
      sshFormFromConnection(connection({ group_id: 5, group_name: "prod" })).groupID,
    ).toBe("5")
    expect(sshFormFromConnection(connection({ group_id: 0 })).groupID).toBe("0")
  })

  test("selects stored-key auth when a key pair is stored", () => {
    const form = sshFormFromConnection(connection({ key_pair_id: 7, key_pair_name: "prod" }))
    expect(form.authMode).toBe("keyPair")
    expect(form.keyPairID).toBe("7")
  })

  test("uses password auth when no key pair is stored", () => {
    const form = sshFormFromConnection(connection({ key_pair_id: 0 }))
    expect(form.authMode).toBe("password")
    expect(form.keyPairID).toBe("0")
  })
})

describe("toSSHRequest", () => {
  test("serializes every blank secret as null, never an empty string", () => {
    const form: SSHFormState = {
      name: "bastion",
      host: "10.0.0.1",
      port: "22",
      username: "root",
      authMode: "password",
      password: "",
      keyPairID: "0",
      proxyHost: "proxy.example",
      proxyPort: "1080",
      proxyUsername: "proxy-user",
      proxyPassword: "",
      jumpIDs: [2, 7, 2, 0, -4, 99],
      defaultDir: "/srv",
      groupID: "0",
    }
    expect(toSSHRequest(form)).toEqual({
      name: "bastion",
      host: "10.0.0.1",
      port: 22,
      username: "root",
      password: null,
      key_pair_id: 0,
      proxy_host: "proxy.example",
      proxy_port: 1080,
      proxy_username: "proxy-user",
      proxy_password: null,
      jump_connection_ids: "[2,7,2,0,-4,99]",
      default_dir: "/srv",
      group_id: 0,
    })
  })

  test("serializes password mode with key_pair_id zero", () => {
    const form: SSHFormState = {
      ...emptySSHForm(),
      name: "bastion",
      host: "10.0.0.1",
      port: "22",
      username: "root",
      password: "hunter2",
      proxyHost: "",
      proxyPort: "1080",
      proxyUsername: "",
      proxyPassword: "proxy-pass",
      jumpIDs: [],
      defaultDir: "",
    }
    const request = toSSHRequest(form)
    expect(request.password).toBe("hunter2")
    expect(request.key_pair_id).toBe(0)
    expect(request.proxy_password).toBe("proxy-pass")
  })

  test("serializes stored-key mode with password null and selected ID", () => {
    const form: SSHFormState = {
      ...emptySSHForm(),
      authMode: "keyPair",
      name: "bastion",
      host: "10.0.0.1",
      port: "22",
      username: "root",
      keyPairID: "7",
      proxyHost: "",
      proxyPort: "1080",
      proxyUsername: "",
      proxyPassword: "proxy-pass",
      jumpIDs: [],
      defaultDir: "",
    }
    const request = toSSHRequest(form)
    expect(request.password).toBeNull()
    expect(request.key_pair_id).toBe(7)
    expect(request.proxy_password).toBe("proxy-pass")
  })

  test("does not trim nonblank secrets", () => {
    const passwordForm: SSHFormState = { ...emptySSHForm(), password: "  spaced  " }
    const passwordRequest = toSSHRequest(passwordForm)
    expect(passwordRequest.password).toBe("  spaced  ")
    expect(passwordRequest.key_pair_id).toBe(0)
  })

  test("maps the group select value to a numeric group_id", () => {
    expect(toSSHRequest({ ...emptySSHForm(), groupID: "5" }).group_id).toBe(5)
    expect(toSSHRequest({ ...emptySSHForm(), groupID: "0" }).group_id).toBe(0)
  })

  test("serializes jump IDs in visible order and numeric inputs as numbers", () => {
    const form: SSHFormState = {
      ...emptySSHForm(),
      port: "2222",
      proxyPort: "1080",
      jumpIDs: [2, 7, 2, 0, -4, 99],
    }
    const request = toSSHRequest(form)
    expect(request.port).toBe(2222)
    expect(request.proxy_port).toBe(1080)
    expect(request.jump_connection_ids).toBe("[2,7,2,0,-4,99]")
  })
})

describe("SSHForm", () => {
  function renderForm(overrides: Partial<Parameters<typeof SSHForm>[0]> = {}) {
    render(
      <SSHForm
        connection={null}
        profiles={[]}
        groups={[]}
        keyPairs={[]}
        pending={false}
        error={null}
        onSubmit={vi.fn()}
        onCancel={vi.fn()}
        {...overrides}
      />,
    )
  }

  test("renders username @ host : port as one inline address row", () => {
    renderForm()
    const username = screen.getByLabelText("Username")
    const host = screen.getByLabelText("Host")
    const port = screen.getByLabelText("Port")

    const row = username.closest(".flex.items-end.gap-2")
    expect(row).not.toBeNull()
    expect(host.closest("div.flex.items-end.gap-2")).toBe(row)
    expect(port.closest("div.flex.items-end.gap-2")).toBe(row)
    expect(within(row as HTMLElement).getByText("@")).toBeInTheDocument()
    expect(within(row as HTMLElement).getByText(":")).toBeInTheDocument()
  })

  test("renders proxy-username @ proxy-host : proxy-port as one inline address row", async () => {
    const user = userEvent.setup()
    renderForm()
    await user.click(screen.getByRole("button", { name: /Server Passthrough/ }))
    const proxyUsername = screen.getByLabelText("Proxy username")
    const proxyHost = screen.getByLabelText("Proxy host")
    const proxyPort = screen.getByLabelText("Proxy port")

    const row = proxyUsername.closest("div.flex.items-end.gap-2")
    expect(row).not.toBeNull()
    expect(proxyHost.closest("div.flex.items-end.gap-2")).toBe(row)
    expect(proxyPort.closest("div.flex.items-end.gap-2")).toBe(row)
    expect(within(row as HTMLElement).getByText("@")).toBeInTheDocument()
    expect(within(row as HTMLElement).getByText(":")).toBeInTheDocument()
  })

  test("starts Server Passthrough closed and marks configured proxy and jump route", () => {
    renderForm({ connection: connection() })

    const passthrough = screen.getByRole("button", { name: /Server Passthrough/ })
    expect(passthrough).toHaveAttribute("aria-expanded", "false")
    expect(within(passthrough).getByText("Proxy")).toBeInTheDocument()
    expect(within(passthrough).getByText("Jump route")).toBeInTheDocument()
    expect(screen.queryByLabelText("Proxy username")).not.toBeInTheDocument()
    expect(screen.queryByRole("combobox", { name: "Add SSH profile to jump route" })).not.toBeInTheDocument()
  })

  test("shows proxy and jump-route settings after opening Server Passthrough", async () => {
    const user = userEvent.setup()
    renderForm()

    await user.click(screen.getByRole("button", { name: /Server Passthrough/ }))

    expect(screen.getByLabelText("Proxy username")).toBeInTheDocument()
    expect(screen.getByText("Jump route")).toBeInTheDocument()
  })

  test("adds Proxy badge when passthrough proxy host is entered", async () => {
    const user = userEvent.setup()
    renderForm()

    const passthrough = screen.getByRole("button", { name: /Server Passthrough/ })
    await user.click(passthrough)
    await user.type(screen.getByLabelText("Proxy host"), "proxy.example")

    expect(within(passthrough).getByText("Proxy")).toBeInTheDocument()
  })

  test("renders password and stored-key auth as mutually exclusive radios", () => {
    renderForm()
    expect(screen.getByText("Authentication mode")).toBeInTheDocument()
    expect(screen.getByRole("radio", { name: "Password" })).toBeChecked()
    expect(screen.getByRole("radio", { name: "Stored key pair" })).not.toBeChecked()
    expect(screen.getByLabelText("Password", { selector: "input" })).toBeInTheDocument()
    expect(screen.queryByRole("combobox", { name: "Stored key pair" })).not.toBeInTheDocument()
  })

  test("switching auth radios clears the inactive mode's selection", async () => {
    const user = userEvent.setup()
    renderForm({ keyPairs: [keyPair(1, "prod")] })

    const passwordInput = screen.getByLabelText("Password", { selector: "input" })
    await user.type(passwordInput, "hunter2")
    expect(passwordInput).toHaveValue("hunter2")

    await user.click(screen.getByRole("radio", { name: "Stored key pair" }))
    const combobox = screen.getByRole("combobox", { name: "Stored key pair" })
    expect(combobox).toHaveTextContent("Select a stored key pair")
    expect(screen.queryByLabelText("Password", { selector: "input" })).not.toBeInTheDocument()

    await user.click(screen.getByRole("radio", { name: "Password" }))
    expect(screen.getByLabelText("Password", { selector: "input" })).toHaveValue("")
    expect(screen.queryByRole("combobox", { name: "Stored key pair" })).not.toBeInTheDocument()
  })

  test("uses plain text inputs for credentials and disables browser autoComplete", async () => {
    const user = userEvent.setup()
    renderForm()
    const form = screen.getByRole("button", { name: "Save" }).closest("form")
    expect(form).not.toBeNull()
    expect(form!.getAttribute("autocomplete")).toBe("off")
    expect(document.getElementById("ssh-password")!.getAttribute("type")).toBeNull()
    await user.click(screen.getByRole("button", { name: /Server Passthrough/ }))
    expect(document.getElementById("ssh-proxy-password")!.getAttribute("type")).toBeNull()
  })

  test("renders a group selector listing None and the available groups", async () => {
    const user = userEvent.setup()
    renderForm({ groups: [group(3, "prod"), group(4, "staging")] })

    await user.click(screen.getByRole("combobox", { name: "Group" }))
    expect(await screen.findByRole("option", { name: "prod" })).toBeInTheDocument()
    expect(screen.getByRole("option", { name: "staging" })).toBeInTheDocument()
    expect(screen.getByRole("option", { name: "None" })).toBeInTheDocument()
  })

  test("shows Missing group #5 when the saved group is absent from the list", () => {
    renderForm({ connection: connection({ group_id: 5 }), groups: [] })

    const combobox = screen.getByRole("combobox", { name: "Group" })
    expect(combobox).toHaveTextContent("Missing group #5")
  })

  test("selecting a group sends its numeric group_id", async () => {
    const user = userEvent.setup()
    const onSubmit = vi.fn()
    renderForm({ groups: [group(3, "prod")], onSubmit })

    await user.type(screen.getByLabelText("Name"), "bastion")
    await user.type(screen.getByLabelText("Host"), "10.0.0.1")
    await user.type(screen.getByLabelText("Username"), "root")
    await user.click(screen.getByRole("combobox", { name: "Group" }))
    await user.click(await screen.findByRole("option", { name: "prod" }))
    await user.click(screen.getByRole("button", { name: "Save" }))
    expect(onSubmit).toHaveBeenCalledWith(expect.objectContaining({ group_id: 3 }))
  })

  test("stored-key mode only offers pairs with private keys", async () => {
    const user = userEvent.setup()
    renderForm({
      keyPairs: [
        keyPair(1, "prod"),
        keyPair(2, "public-only", { has_private_key: false }),
      ],
    })

    await user.click(screen.getByRole("radio", { name: "Stored key pair" }))
    await user.click(screen.getByRole("combobox", { name: "Stored key pair" }))
    expect(await screen.findByRole("option", { name: "prod" })).toBeInTheDocument()
    expect(screen.queryByRole("option", { name: "public-only" })).not.toBeInTheDocument()
  })

  test("preserves missing selected key-pair ID as a visible option", () => {
    renderForm({ connection: connection({ key_pair_id: 7 }), keyPairs: [] })

    const combobox = screen.getByRole("combobox", { name: "Stored key pair" })
    expect(combobox).toHaveTextContent("Missing key pair #7")
  })

  test("requires a stored key-pair selection in stored-key mode", async () => {
    const user = userEvent.setup()
    const onSubmit = vi.fn()
    renderForm({ onSubmit })

    await user.type(screen.getByLabelText("Name"), "bastion")
    await user.type(screen.getByLabelText("Host"), "10.0.0.1")
    await user.type(screen.getByLabelText("Username"), "root")
    await user.click(screen.getByRole("radio", { name: "Stored key pair" }))
    await user.click(screen.getByRole("button", { name: "Save" }))

    expect(screen.getByRole("alert")).toHaveTextContent("Select a stored key pair.")
    expect(onSubmit).not.toHaveBeenCalled()
  })

  test("renders form errors with role alert", () => {
    render(
      <SSHForm
        connection={null}
        profiles={[]}
        groups={[]}
        keyPairs={[]}
        pending={false}
        error="a connection with that name already exists"
        onSubmit={vi.fn()}
        onCancel={vi.fn()}
      />,
    )
    const alert = screen.getByRole("alert")
    expect(alert).toHaveTextContent("a connection with that name already exists")
  })
})
