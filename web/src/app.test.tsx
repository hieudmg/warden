import { act, render, screen, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { useState } from "react"
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest"
import { App, Notifications } from "./app"
import { api } from "@/api/client"
import type { SSHConnection, DBConnection, Group, KeyPairSummary, Project } from "./api/types"

vi.mock("@/api/client", () => ({
  api: {
    listSSH: vi.fn(),
    listDB: vi.fn(),
    listGroups: vi.fn(),
    listProjects: vi.fn(),
    listKeyPairs: vi.fn(),
    createSSH: vi.fn(),
    updateSSH: vi.fn(),
    deleteSSH: vi.fn(),
    sshDependents: vi.fn(),
    createDB: vi.fn(),
    updateDB: vi.fn(),
    deleteDB: vi.fn(),
    dbDependents: vi.fn(),
    createGroup: vi.fn(),
    updateGroup: vi.fn(),
    deleteGroup: vi.fn(),
    groupDependents: vi.fn(),
    getKeyPair: vi.fn(),
    createKeyPair: vi.fn(),
    updateKeyPair: vi.fn(),
    deleteKeyPair: vi.fn(),
    keyPairDependents: vi.fn(),
    listReports: vi.fn(),
    createProject: vi.fn(),
    createReport: vi.fn(),
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
    group_id: 0,
    created_at: "2026-08-24T00:00:00Z",
    updated_at: "2026-08-24T00:00:00Z",
  }
}

function project(id: number): Project {
  return { id, name: `project-${id}` }
}

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

function keyPair(id: number): KeyPairSummary {
  return {
    id,
    name: `pair-${id}`,
    has_public_key: true,
    has_private_key: true,
    has_private_key_passphrase: false,
    created_at: "2026-08-26T00:00:00Z",
    updated_at: "2026-08-26T00:00:00Z",
  }
}

beforeEach(() => {
  mockedAPI.listSSH.mockReset().mockResolvedValue([sshConnection(1)])
  mockedAPI.listDB.mockReset().mockResolvedValue([dbConnection(1)])
  mockedAPI.listGroups.mockReset().mockResolvedValue([group(1, "prod")])
  mockedAPI.listProjects.mockReset().mockResolvedValue([project(1)])
  mockedAPI.listKeyPairs.mockReset().mockResolvedValue([keyPair(1)])
  mockedAPI.listReports.mockReset().mockResolvedValue([])
  mockedAPI.createProject.mockReset().mockResolvedValue({ id: 2, name: "project-2" })
  mockedAPI.createReport.mockReset().mockResolvedValue({
    id: 1,
    project: "project-1",
    title: "report",
    summary: "summary",
    agent_model: "gpt-4o",
    created_at: "2026-08-24T00:00:00Z",
  })
})

describe("App", () => {
  test("renders the light Warden shell with SSH selected initially", async () => {
    render(<App />)

    expect(screen.getByRole("heading", { name: "Warden Hub" })).toBeInTheDocument()
    expect(document.documentElement).not.toHaveClass("dark")

    const sshTab = screen.getByRole("tab", { name: "SSH" })
    const dbTab = screen.getByRole("tab", { name: "Databases" })
    const groupsTab = screen.getByRole("tab", { name: "Groups" })
    const keyPairsTab = screen.getByRole("tab", { name: "Key Pairs" })
    const projectsTab = screen.getByRole("tab", { name: "Projects & Reports" })

    expect(sshTab).toHaveAttribute("aria-selected", "true")
    expect(dbTab).toHaveAttribute("aria-selected", "false")
    expect(groupsTab).toHaveAttribute("aria-selected", "false")
    expect(keyPairsTab).toHaveAttribute("aria-selected", "false")
    expect(projectsTab).toHaveAttribute("aria-selected", "false")
  })

  test("loads all five list resources concurrently on mount", async () => {
    render(<App />)

    expect(mockedAPI.listSSH).toHaveBeenCalledTimes(1)
    expect(mockedAPI.listDB).toHaveBeenCalledTimes(1)
    expect(mockedAPI.listGroups).toHaveBeenCalledTimes(1)
    expect(mockedAPI.listProjects).toHaveBeenCalledTimes(1)
    expect(mockedAPI.listKeyPairs).toHaveBeenCalledTimes(1)
  })

  test("switches between module tabs by accessible tab roles", async () => {
    const user = userEvent.setup()
    render(<App />)

    const sshTab = screen.getByRole("tab", { name: "SSH" })
    const dbTab = screen.getByRole("tab", { name: "Databases" })
    const groupsTab = screen.getByRole("tab", { name: "Groups" })
    const keyPairsTab = screen.getByRole("tab", { name: "Key Pairs" })
    const projectsTab = screen.getByRole("tab", { name: "Projects & Reports" })

    await user.click(dbTab)
    expect(dbTab).toHaveAttribute("aria-selected", "true")
    expect(sshTab).toHaveAttribute("aria-selected", "false")

    await user.click(groupsTab)
    expect(groupsTab).toHaveAttribute("aria-selected", "true")
    expect(dbTab).toHaveAttribute("aria-selected", "false")

    await user.click(keyPairsTab)
    expect(keyPairsTab).toHaveAttribute("aria-selected", "true")
    expect(groupsTab).toHaveAttribute("aria-selected", "false")

    await user.click(projectsTab)
    expect(projectsTab).toHaveAttribute("aria-selected", "true")
    expect(keyPairsTab).toHaveAttribute("aria-selected", "false")
  })

  test("switches tabs with arrow keys following Radix behavior", async () => {
    const user = userEvent.setup()
    render(<App />)

    const sshTab = screen.getByRole("tab", { name: "SSH" })
    const dbTab = screen.getByRole("tab", { name: "Databases" })
    const groupsTab = screen.getByRole("tab", { name: "Groups" })
    const keyPairsTab = screen.getByRole("tab", { name: "Key Pairs" })
    const projectsTab = screen.getByRole("tab", { name: "Projects & Reports" })

    sshTab.focus()
    await user.keyboard("{ArrowRight}")
    expect(dbTab).toHaveAttribute("aria-selected", "true")
    expect(sshTab).toHaveAttribute("aria-selected", "false")

    await user.keyboard("{ArrowRight}")
    expect(groupsTab).toHaveAttribute("aria-selected", "true")
    expect(dbTab).toHaveAttribute("aria-selected", "false")

    await user.keyboard("{ArrowRight}")
    expect(keyPairsTab).toHaveAttribute("aria-selected", "true")
    expect(groupsTab).toHaveAttribute("aria-selected", "false")

    await user.keyboard("{ArrowRight}")
    expect(projectsTab).toHaveAttribute("aria-selected", "true")
    expect(keyPairsTab).toHaveAttribute("aria-selected", "false")

    await user.keyboard("{ArrowLeft}")
    expect(keyPairsTab).toHaveAttribute("aria-selected", "true")
    expect(projectsTab).toHaveAttribute("aria-selected", "false")

    await user.keyboard("{ArrowLeft}")
    expect(groupsTab).toHaveAttribute("aria-selected", "true")
    expect(keyPairsTab).toHaveAttribute("aria-selected", "false")
  })

  test("renders group rows when the Groups tab is active", async () => {
    const user = userEvent.setup()
    render(<App />)

    await user.click(screen.getByRole("tab", { name: "Groups" }))
    expect(await screen.findByText("prod")).toBeInTheDocument()
    expect(screen.getByText("SSH 0 · DB 0")).toBeInTheDocument()
  })

  test("renders key-pair rows when the Key Pairs tab is active", async () => {
    const user = userEvent.setup()
    render(<App />)

    expect(mockedAPI.listKeyPairs).toHaveBeenCalledTimes(1)
    await user.click(screen.getByRole("tab", { name: "Key Pairs" }))
    expect(await screen.findByRole("heading", { name: "Key pairs" })).toBeInTheDocument()
    expect(await screen.findByText("pair-1")).toBeInTheDocument()
  })

  test("passes key-pair summaries to the SSH form after resources resolve", async () => {
    const user = userEvent.setup()
    render(<App />)

    await user.click(screen.getByRole("button", { name: "New connection" }))
    const dialog = await screen.findByRole("dialog")
    await user.click(within(dialog).getByRole("radio", { name: "Stored key pair" }))
    await user.click(within(dialog).getByRole("combobox", { name: "Stored key pair" }))
    expect(await within(dialog).findByRole("option", { name: "pair-1" })).toBeInTheDocument()
  })
})

describe("Notifications", () => {
  afterEach(() => {
    vi.useRealTimers()
  })

  test("renders success toast with polite live region and dismiss control", () => {
    render(
      <Notifications
        items={[{ id: 1, message: "Connection saved.", kind: "success" }]}
        onDismiss={() => {}}
      />,
    )
    const toast = screen.getByText("Connection saved.").closest("[data-slot='toast']")
    expect(toast).toHaveAttribute("role", "status")
    expect(toast).toHaveAttribute("aria-live", "polite")
    expect(screen.getByRole("button", { name: "Close" })).toBeInTheDocument()
  })

  test("renders error toast with alert role", () => {
    render(
      <Notifications
        items={[{ id: 2, message: "Unable to connect.", kind: "error" }]}
        onDismiss={() => {}}
      />,
    )
    const alert = screen.getByRole("alert")
    expect(alert).toHaveTextContent("Unable to connect.")
  })

  test("removes toast after 10 seconds", () => {
    vi.useFakeTimers()

    function ToastHarness() {
      const [items, setItems] = useState([{ id: 1, message: "Created.", kind: "success" as const }])
      return (
        <Notifications
          items={items}
          onDismiss={(id: number) => setItems((current) => current.filter((item) => item.id !== id))}
        />
      )
    }

    render(<ToastHarness />)
    expect(screen.getByText("Created.").closest("[data-slot='toast']")).toHaveAttribute("role", "status")

    act(() => vi.advanceTimersByTime(10_000))

    expect(screen.queryByText("Created.")).not.toBeInTheDocument()
  })

  test("removes toast when its dismiss control is clicked", async () => {
    const user = userEvent.setup()

    function ToastHarness() {
      const [items, setItems] = useState([{ id: 1, message: "Created.", kind: "success" as const }])
      return (
        <Notifications
          items={items}
          onDismiss={(id: number) => setItems((current) => current.filter((item) => item.id !== id))}
        />
      )
    }

    render(<ToastHarness />)
    await user.click(screen.getByRole("button", { name: "Close" }))

    expect(screen.queryByText("Created.")).not.toBeInTheDocument()
  })
})
