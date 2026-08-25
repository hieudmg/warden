import { render, screen, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { describe, expect, test, vi } from "vitest"
import type { Group, SSHConnection } from "@/api/types"
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

function connection(overrides: Partial<SSHConnection> = {}): SSHConnection {
  return {
    id: 1,
    name: "bastion",
    host: "10.0.0.1",
    port: 22,
    username: "root",
    has_password: true,
    has_private_key: true,
    has_private_key_passphrase: true,
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
    expect(form.privateKey).toBe("")
    expect(form.privateKeyPassphrase).toBe("")
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
    expect(form.privateKey).toBe("")
    expect(form.privateKeyPassphrase).toBe("")
    expect(form.proxyPassword).toBe("")
  })

  test("maps the saved group id to a string value", () => {
    expect(
      sshFormFromConnection(connection({ group_id: 5, group_name: "prod" })).groupID,
    ).toBe("5")
    expect(sshFormFromConnection(connection({ group_id: 0 })).groupID).toBe("0")
  })

  test("infers private-key auth when only a private key is stored", () => {
    const form = sshFormFromConnection(
      connection({ has_password: false, has_private_key: true, has_private_key_passphrase: true }),
    )
    expect(form.authMode).toBe("privateKey")
  })

  test("infers password auth when only a password is stored", () => {
    const form = sshFormFromConnection(
      connection({ has_password: true, has_private_key: false, has_private_key_passphrase: false }),
    )
    expect(form.authMode).toBe("password")
  })

  test("prefers password auth when both secrets are stored", () => {
    const form = sshFormFromConnection(
      connection({ has_password: true, has_private_key: true, has_private_key_passphrase: true }),
    )
    expect(form.authMode).toBe("password")
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
      privateKey: "",
      privateKeyPassphrase: "",
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
      private_key: null,
      private_key_passphrase: null,
      proxy_host: "proxy.example",
      proxy_port: 1080,
      proxy_username: "proxy-user",
      proxy_password: null,
      jump_connection_ids: "[2,7,2,0,-4,99]",
      default_dir: "/srv",
      group_id: 0,
    })
  })

  test("serializes password mode with the password preserved and key fields null", () => {
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
    expect(request.private_key).toBeNull()
    expect(request.private_key_passphrase).toBeNull()
    expect(request.proxy_password).toBe("proxy-pass")
  })

  test("serializes private-key mode with key fields preserved and password null", () => {
    const form: SSHFormState = {
      ...emptySSHForm(),
      authMode: "privateKey",
      name: "bastion",
      host: "10.0.0.1",
      port: "22",
      username: "root",
      privateKey: "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n-----END OPENSSH PRIVATE KEY-----",
      privateKeyPassphrase: "key-pass",
      proxyHost: "",
      proxyPort: "1080",
      proxyUsername: "",
      proxyPassword: "proxy-pass",
      jumpIDs: [],
      defaultDir: "",
    }
    const request = toSSHRequest(form)
    expect(request.password).toBeNull()
    expect(request.private_key).toBe(
      "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n-----END OPENSSH PRIVATE KEY-----",
    )
    expect(request.private_key_passphrase).toBe("key-pass")
    expect(request.proxy_password).toBe("proxy-pass")
  })

  test("does not trim nonblank secrets", () => {
    const passwordForm: SSHFormState = { ...emptySSHForm(), password: "  spaced  " }
    const passwordRequest = toSSHRequest(passwordForm)
    expect(passwordRequest.password).toBe("  spaced  ")
    expect(passwordRequest.private_key).toBeNull()

    const keyForm: SSHFormState = {
      ...emptySSHForm(),
      authMode: "privateKey",
      privateKey: "  key  ",
    }
    const keyRequest = toSSHRequest(keyForm)
    expect(keyRequest.private_key).toBe("  key  ")
    expect(keyRequest.password).toBeNull()
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

  test("renders password and private-key auth as mutually exclusive radios", () => {
    renderForm()
    expect(screen.getByText("Authentication mode")).toBeInTheDocument()
    expect(screen.getByRole("radio", { name: "Password" })).toBeChecked()
    expect(screen.getByRole("radio", { name: "Private key" })).not.toBeChecked()
    expect(screen.getByLabelText("Password", { selector: "input" })).toBeInTheDocument()
    expect(screen.queryByLabelText("Private key", { selector: "textarea" })).not.toBeInTheDocument()
  })

  test("switching auth radios clears the inactive mode's secret", async () => {
    const user = userEvent.setup()
    renderForm()

    const passwordInput = screen.getByLabelText("Password", { selector: "input" })
    await user.type(passwordInput, "hunter2")
    expect(passwordInput).toHaveValue("hunter2")

    await user.click(screen.getByRole("radio", { name: "Private key" }))
    expect(screen.getByLabelText("Private key", { selector: "textarea" })).toHaveValue("")
    expect(
      screen.getByLabelText("Private key passphrase", { selector: "input" }),
    ).toHaveValue("")
    expect(screen.queryByLabelText("Password", { selector: "input" })).not.toBeInTheDocument()

    await user.click(screen.getByRole("radio", { name: "Password" }))
    expect(screen.getByLabelText("Password", { selector: "input" })).toHaveValue("")
    expect(screen.queryByLabelText("Private key", { selector: "textarea" })).not.toBeInTheDocument()
  })

  test("uses plain text inputs for credentials and disables browser autoComplete", async () => {
    const user = userEvent.setup()
    renderForm()
    const form = screen.getByRole("button", { name: "Save" }).closest("form")
    expect(form).not.toBeNull()
    expect(form!.getAttribute("autocomplete")).toBe("off")
    expect(document.getElementById("ssh-password")!.getAttribute("type")).toBeNull()
    // The passphrase input only mounts once the user picks private-key auth.
    await user.click(screen.getByRole("radio", { name: "Private key" }))
    expect(document.getElementById("ssh-private-key-passphrase")!.getAttribute("type")).toBeNull()
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

  test("renders form errors with role alert", () => {
    render(
      <SSHForm
        connection={null}
        profiles={[]}
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
})
