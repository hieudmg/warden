import { render, screen, within } from "@testing-library/react"
import { describe, expect, test, vi } from "vitest"
import type { SSHConnection } from "@/api/types"
import { emptySSHForm, sshFormFromConnection, toSSHRequest, type SSHFormState } from "./ssh-form"
import { SSHForm } from "./ssh-form"

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
    created_at: "2026-08-24T00:00:00Z",
    updated_at: "2026-08-24T00:00:00Z",
    ...overrides,
  }
}

describe("emptySSHForm", () => {
  test("defaults ports to 22 and 1080 with an empty route and blank secrets", () => {
    const form = emptySSHForm()
    expect(form.port).toBe("22")
    expect(form.proxyPort).toBe("1080")
    expect(form.jumpIDs).toEqual([])
    expect(form.password).toBe("")
    expect(form.privateKey).toBe("")
    expect(form.privateKeyPassphrase).toBe("")
    expect(form.proxyPassword).toBe("")
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
})

describe("toSSHRequest", () => {
  test("serializes every blank secret as null, never an empty string", () => {
    const form: SSHFormState = {
      name: "bastion",
      host: "10.0.0.1",
      port: "22",
      username: "root",
      password: "",
      privateKey: "",
      privateKeyPassphrase: "",
      proxyHost: "proxy.example",
      proxyPort: "1080",
      proxyUsername: "proxy-user",
      proxyPassword: "",
      jumpIDs: [2, 7, 2, 0, -4, 99],
      defaultDir: "/srv",
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
    })
  })

  test("preserves each nonblank secret independently", () => {
    const form: SSHFormState = {
      ...emptySSHForm(),
      name: "bastion",
      host: "10.0.0.1",
      port: "22",
      username: "root",
      password: "hunter2",
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
    expect(request.password).toBe("hunter2")
    expect(request.private_key).toBe(
      "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n-----END OPENSSH PRIVATE KEY-----",
    )
    expect(request.private_key_passphrase).toBe("key-pass")
    expect(request.proxy_password).toBe("proxy-pass")
  })

  test("does not trim nonblank secrets", () => {
    const form: SSHFormState = { ...emptySSHForm(), password: "  spaced  ", privateKey: "  key  " }
    const request = toSSHRequest(form)
    expect(request.password).toBe("  spaced  ")
    expect(request.private_key).toBe("  key  ")
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
  function renderForm() {
    render(
      <SSHForm
        connection={null}
        profiles={[]}
        pending={false}
        error={null}
        onSubmit={vi.fn()}
        onCancel={vi.fn()}
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

  test("renders proxy-username @ proxy-host : proxy-port as one inline address row", () => {
    renderForm()
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

  test("renders form errors with role alert", () => {
    render(
      <SSHForm
        connection={null}
        profiles={[]}
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
