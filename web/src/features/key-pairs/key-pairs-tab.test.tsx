import { act, render, screen, waitFor, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { beforeEach, describe, expect, test, vi } from "vitest"
import { api, ApiError } from "@/api/client"
import type { KeyPairSummary, KeyPairVault } from "@/api/types"
import type { ListResource } from "@/hooks/use-list-resource"
import { KeyPairsTab } from "./key-pairs-tab"

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
      getKeyPair: vi.fn(),
      createKeyPair: vi.fn(),
      updateKeyPair: vi.fn(),
      deleteKeyPair: vi.fn(),
      keyPairDependents: vi.fn(),
    },
    ApiError: MockApiError,
  }
})

const mockedAPI = vi.mocked(api)

function keyPair(id: number, name: string, overrides: Partial<KeyPairSummary> = {}): KeyPairSummary {
  return {
    id,
    name,
    has_public_key: true,
    has_private_key: true,
    has_private_key_passphrase: true,
    created_at: "2026-08-26T00:00:00Z",
    updated_at: "2026-08-26T00:00:00Z",
    ...overrides,
  }
}

function vault(id: number, name: string, overrides: Partial<KeyPairVault> = {}): KeyPairVault {
  return {
    ...keyPair(id, name),
    public_key: "PUBLIC-KEY-MATERIAL",
    private_key: "PRIVATE-KEY-MATERIAL",
    private_key_passphrase: "PHRASE-MATERIAL",
    ...overrides,
  }
}

function resource(overrides: Partial<ListResource<KeyPairSummary>> = {}): ListResource<KeyPairSummary> {
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
  mockedAPI.getKeyPair.mockReset()
  mockedAPI.createKeyPair.mockReset()
  mockedAPI.updateKeyPair.mockReset()
  mockedAPI.deleteKeyPair.mockReset()
  mockedAPI.keyPairDependents.mockReset()
  notify.mockReset()
})

describe("KeyPairsTab", () => {
  test("shows a loading state while the resource loads", () => {
    render(<KeyPairsTab resource={resource({ loading: true })} notify={notify} />)
    expect(screen.getByText("Loading…")).toBeInTheDocument()
  })

  test("shows an empty state when no key pairs exist", () => {
    render(<KeyPairsTab resource={resource({ data: [] })} notify={notify} />)
    expect(screen.getByText("No key pairs yet.")).toBeInTheDocument()
  })

  test("shows a load error with a Retry action", async () => {
    const user = userEvent.setup()
    const reload = vi.fn().mockResolvedValue(undefined)
    render(<KeyPairsTab resource={resource({ error: new Error("boom"), reload })} notify={notify} />)

    expect(screen.getByRole("alert")).toHaveTextContent("Unable to load key pairs")
    await user.click(screen.getByRole("button", { name: "Retry" }))
    expect(reload).toHaveBeenCalledTimes(1)
  })

  test("renders rows with presence badges and filters by name case-insensitively", async () => {
    const user = userEvent.setup()
    render(
      <KeyPairsTab
        resource={resource({
          data: [
            keyPair(1, "prod"),
            keyPair(2, "staging", { has_public_key: false, has_private_key_passphrase: false }),
          ],
        })}
        notify={notify}
      />,
    )

    expect(screen.getByText("prod")).toBeInTheDocument()
    expect(screen.getByText("Public key")).toBeInTheDocument()
    expect(screen.getAllByText("Private key")).toHaveLength(2)
    expect(screen.getByText("Passphrase")).toBeInTheDocument()
    expect(screen.getByText("staging")).toBeInTheDocument()

    await user.type(screen.getByLabelText("Search key pairs"), "STAG")
    expect(screen.queryByText("prod")).not.toBeInTheDocument()
    expect(screen.getByText("staging")).toBeInTheDocument()
    expect(screen.queryByText("Public key")).not.toBeInTheDocument()
    expect(screen.getAllByText("Private key")).toHaveLength(1)
  })

  test("creates a key pair through the dialog, reloads, and notifies", async () => {
    const user = userEvent.setup()
    const reload = vi.fn().mockResolvedValue(undefined)
    mockedAPI.createKeyPair.mockResolvedValue(keyPair(1, "prod"))
    render(<KeyPairsTab resource={resource({ data: [], reload })} notify={notify} />)

    await user.click(screen.getByRole("button", { name: "New key pair" }))
    const dialog = await screen.findByRole("dialog")
    await user.type(within(dialog).getByLabelText("Name"), "prod")
    await user.type(within(dialog).getByLabelText("Public key"), "PUBLIC-KEY-MATERIAL")
    await user.click(within(dialog).getByRole("button", { name: "Save" }))

    await waitFor(() => expect(mockedAPI.createKeyPair).toHaveBeenCalledTimes(1))
    expect(mockedAPI.createKeyPair).toHaveBeenCalledWith({
      name: "prod",
      public_key: "PUBLIC-KEY-MATERIAL",
      private_key: null,
      private_key_passphrase: null,
    })
    expect(reload).toHaveBeenCalledTimes(1)
    expect(notify).toHaveBeenCalledWith('Created key pair "prod".', "success")
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument())
  })

  test("loads the vault before edit fields appear", async () => {
    const user = userEvent.setup()
    let resolveVault: (value: KeyPairVault) => void = () => {}
    mockedAPI.getKeyPair.mockReturnValue(
      new Promise<KeyPairVault>(resolve => {
        resolveVault = resolve
      }),
    )
    render(<KeyPairsTab resource={resource({ data: [keyPair(1, "prod")] })} notify={notify} />)

    await user.click(screen.getByRole("button", { name: "Edit prod" }))
    const dialog = await screen.findByRole("dialog")
    expect(mockedAPI.getKeyPair).toHaveBeenCalledWith(1)
    expect(within(dialog).getByText("Loading vault…")).toBeInTheDocument()
    expect(within(dialog).queryByLabelText("Public key")).not.toBeInTheDocument()
    expect(within(dialog).queryByLabelText("Private key")).not.toBeInTheDocument()
    expect(within(dialog).queryByLabelText("Private key passphrase")).not.toBeInTheDocument()

    await act(async () => {
      resolveVault(vault(1, "prod"))
    })

    expect(await within(dialog).findByLabelText("Public key")).toHaveValue("PUBLIC-KEY-MATERIAL")
    expect(within(dialog).getByLabelText("Private key")).toHaveValue("PRIVATE-KEY-MATERIAL")
    expect(within(dialog).getByLabelText("Private key passphrase")).toHaveValue("PHRASE-MATERIAL")
    expect(within(dialog).queryByText("Loading vault…")).not.toBeInTheDocument()
  })

  test("edits the private key and passphrase without touching unchanged fields", async () => {
    const user = userEvent.setup()
    const reload = vi.fn().mockResolvedValue(undefined)
    mockedAPI.getKeyPair.mockResolvedValue(vault(1, "prod"))
    mockedAPI.updateKeyPair.mockResolvedValue(keyPair(1, "prod"))
    render(<KeyPairsTab resource={resource({ data: [keyPair(1, "prod")], reload })} notify={notify} />)

    await user.click(screen.getByRole("button", { name: "Edit prod" }))
    const dialog = await screen.findByRole("dialog")
    const privateKey = await within(dialog).findByLabelText("Private key")
    expect(privateKey).toHaveValue("PRIVATE-KEY-MATERIAL")

    await user.clear(privateKey)
    await user.type(privateKey, "NEW-PRIVATE-KEY")
    const passphrase = within(dialog).getByLabelText("Private key passphrase")
    await user.clear(passphrase)
    await user.type(passphrase, "NEW-PHRASE")
    await user.click(within(dialog).getByRole("button", { name: "Save" }))

    await waitFor(() => expect(mockedAPI.updateKeyPair).toHaveBeenCalledTimes(1))
    expect(mockedAPI.updateKeyPair).toHaveBeenCalledWith(1, {
      name: "prod",
      public_key: null,
      private_key: "NEW-PRIVATE-KEY",
      private_key_passphrase: "NEW-PHRASE",
    })
    expect(reload).toHaveBeenCalledTimes(1)
    expect(notify).toHaveBeenCalledWith('Updated key pair "prod".', "success")
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument())
  })

  test("clears a secret field explicitly with the clear button", async () => {
    const user = userEvent.setup()
    const reload = vi.fn().mockResolvedValue(undefined)
    mockedAPI.getKeyPair.mockResolvedValue(vault(1, "prod"))
    mockedAPI.updateKeyPair.mockResolvedValue(keyPair(1, "prod"))
    render(<KeyPairsTab resource={resource({ data: [keyPair(1, "prod")], reload })} notify={notify} />)

    await user.click(screen.getByRole("button", { name: "Edit prod" }))
    const dialog = await screen.findByRole("dialog")
    expect(await within(dialog).findByLabelText("Private key")).toHaveValue("PRIVATE-KEY-MATERIAL")

    await user.click(within(dialog).getByRole("button", { name: "Clear private key" }))
    expect(within(dialog).getByLabelText("Private key")).toHaveValue("")

    await user.click(within(dialog).getByRole("button", { name: "Save" }))

    await waitFor(() => expect(mockedAPI.updateKeyPair).toHaveBeenCalledTimes(1))
    expect(mockedAPI.updateKeyPair).toHaveBeenCalledWith(1, {
      name: "prod",
      public_key: null,
      private_key: "",
      private_key_passphrase: null,
    })
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument())
  })

  test("warns about referencing SSH connections before deletion", async () => {
    const user = userEvent.setup()
    const reload = vi.fn().mockResolvedValue(undefined)
    mockedAPI.keyPairDependents.mockResolvedValue({
      ssh: [
        { id: 2, name: "jump-a" },
        { id: 3, name: "bastion" },
      ],
      db: [],
    })
    mockedAPI.deleteKeyPair.mockResolvedValue(undefined)
    render(<KeyPairsTab resource={resource({ data: [keyPair(1, "prod")], reload })} notify={notify} />)

    await user.click(screen.getByRole("button", { name: "Delete prod" }))
    const dialog = await screen.findByRole("dialog")
    expect(mockedAPI.keyPairDependents).toHaveBeenCalledWith(1)
    expect(await within(dialog).findByText("jump-a (SSH)")).toBeInTheDocument()
    expect(within(dialog).getByText("bastion (SSH)")).toBeInTheDocument()
    await user.click(within(dialog).getByRole("button", { name: "Delete" }))

    await waitFor(() => expect(mockedAPI.deleteKeyPair).toHaveBeenCalledWith(1))
    expect(reload).toHaveBeenCalledTimes(1)
    expect(notify).toHaveBeenCalledWith('Deleted key pair "prod".', "success")
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument())
  })

  test("permits deletion when the dependents lookup fails", async () => {
    const user = userEvent.setup()
    const reload = vi.fn().mockResolvedValue(undefined)
    mockedAPI.keyPairDependents.mockRejectedValue(new Error("network unavailable"))
    mockedAPI.deleteKeyPair.mockResolvedValue(undefined)
    render(<KeyPairsTab resource={resource({ data: [keyPair(1, "prod")], reload })} notify={notify} />)

    await user.click(screen.getByRole("button", { name: "Delete prod" }))
    const dialog = await screen.findByRole("dialog")
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      "Unable to check for dependents: network unavailable",
    )

    const deleteButton = within(dialog).getByRole("button", { name: "Delete" })
    expect(deleteButton).toBeEnabled()
    await user.click(deleteButton)

    await waitFor(() => expect(mockedAPI.deleteKeyPair).toHaveBeenCalledWith(1))
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument())
  })

  test("returns focus to the trigger when the edit dialog closes", async () => {
    const user = userEvent.setup()
    mockedAPI.getKeyPair.mockResolvedValue(vault(1, "prod"))
    render(<KeyPairsTab resource={resource({ data: [keyPair(1, "prod")] })} notify={notify} />)

    const trigger = screen.getByRole("button", { name: "Edit prod" })
    await user.click(trigger)
    const dialog = await screen.findByRole("dialog")
    expect(await within(dialog).findByLabelText("Private key")).toBeInTheDocument()

    await user.keyboard("{Escape}")
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument())
    expect(trigger).toHaveFocus()
  })

  test("keeps the dialog open with a server error after a rejected submit", async () => {
    const user = userEvent.setup()
    mockedAPI.createKeyPair.mockRejectedValue(
      new ApiError("conflict", "a key pair with that name already exists", 409),
    )
    render(<KeyPairsTab resource={resource({ data: [] })} notify={notify} />)

    await user.click(screen.getByRole("button", { name: "New key pair" }))
    const dialog = await screen.findByRole("dialog")
    await user.type(within(dialog).getByLabelText("Name"), "dup")
    await user.click(within(dialog).getByRole("button", { name: "Save" }))

    const alert = await within(dialog).findByRole("alert")
    expect(alert).toHaveTextContent("a key pair with that name already exists")
    expect(within(dialog).getByLabelText("Name")).toHaveValue("dup")
    expect(screen.getByRole("dialog")).toBeInTheDocument()
  })
})
