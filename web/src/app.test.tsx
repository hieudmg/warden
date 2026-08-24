import { render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { beforeEach, describe, expect, test, vi } from "vitest"
import { App, Notifications } from "./app"
import { api } from "@/api/client"
import type { SSHConnection, DBConnection, Project } from "./api/types"

vi.mock("@/api/client", () => ({
  api: {
    listSSH: vi.fn(),
    listDB: vi.fn(),
    listProjects: vi.fn(),
    createSSH: vi.fn(),
    updateSSH: vi.fn(),
    deleteSSH: vi.fn(),
    sshDependents: vi.fn(),
    createDB: vi.fn(),
    updateDB: vi.fn(),
    deleteDB: vi.fn(),
    dbDependents: vi.fn(),
  },
}))

const mockedAPI = vi.mocked(api)

function sshConnection(id: number): SSHConnection {
  return {
    id,
    name: `ssh-${id}`,
    host: "10.0.0.1",
    port: 22,
    username: "root",
    has_password: true,
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
  }
}

function dbConnection(id: number): DBConnection {
  return {
    id,
    name: `db-${id}`,
    host: "127.0.0.1",
    port: 3306,
    username: "app",
    has_password: true,
    database: "warden",
    ssh_connection_id: 0,
    created_at: "2026-08-24T00:00:00Z",
    updated_at: "2026-08-24T00:00:00Z",
  }
}

function project(id: number): Project {
  return { id, name: `project-${id}` }
}

beforeEach(() => {
  mockedAPI.listSSH.mockReset().mockResolvedValue([sshConnection(1)])
  mockedAPI.listDB.mockReset().mockResolvedValue([dbConnection(1)])
  mockedAPI.listProjects.mockReset().mockResolvedValue([project(1)])
})

describe("App", () => {
  test("renders the light Warden shell with SSH selected initially", async () => {
    render(<App />)

    expect(screen.getByRole("heading", { name: "Warden Hub" })).toBeInTheDocument()
    expect(document.documentElement).not.toHaveClass("dark")

    const sshTab = screen.getByRole("tab", { name: "SSH" })
    const dbTab = screen.getByRole("tab", { name: "Databases" })
    const projectsTab = screen.getByRole("tab", { name: "Projects & Reports" })

    expect(sshTab).toHaveAttribute("aria-selected", "true")
    expect(dbTab).toHaveAttribute("aria-selected", "false")
    expect(projectsTab).toHaveAttribute("aria-selected", "false")
  })

  test("loads all three list resources concurrently on mount", async () => {
    render(<App />)

    expect(mockedAPI.listSSH).toHaveBeenCalledTimes(1)
    expect(mockedAPI.listDB).toHaveBeenCalledTimes(1)
    expect(mockedAPI.listProjects).toHaveBeenCalledTimes(1)
  })

  test("switches between module tabs by accessible tab roles", async () => {
    const user = userEvent.setup()
    render(<App />)

    const sshTab = screen.getByRole("tab", { name: "SSH" })
    const dbTab = screen.getByRole("tab", { name: "Databases" })
    const projectsTab = screen.getByRole("tab", { name: "Projects & Reports" })

    await user.click(dbTab)
    expect(dbTab).toHaveAttribute("aria-selected", "true")
    expect(sshTab).toHaveAttribute("aria-selected", "false")

    await user.click(projectsTab)
    expect(projectsTab).toHaveAttribute("aria-selected", "true")
    expect(dbTab).toHaveAttribute("aria-selected", "false")
  })
})

describe("Notifications", () => {
  test("renders success notifications with polite live region", () => {
    render(
      <Notifications
        items={[{ id: 1, message: "Connection saved.", kind: "success" }]}
      />,
    )
    const region = screen.getByRole("status")
    expect(region).toHaveAttribute("aria-live", "polite")
    expect(region).toHaveTextContent("Connection saved.")
  })

  test("renders error notifications with alert role", () => {
    render(
      <Notifications
        items={[{ id: 2, message: "Unable to connect.", kind: "error" }]}
      />,
    )
    const alert = screen.getByRole("alert")
    expect(alert).toHaveTextContent("Unable to connect.")
  })

  test("renders both kinds in order", () => {
    render(
      <Notifications
        items={[
          { id: 1, message: "Created.", kind: "success" },
          { id: 2, message: "Delete failed.", kind: "error" },
        ]}
      />,
    )
    const alerts = screen.getAllByRole("alert")
    const status = screen.getByRole("status")
    expect(alerts).toHaveLength(1)
    expect(status).toHaveTextContent("Created.")
    expect(alerts[0]).toHaveTextContent("Delete failed.")
  })
})
