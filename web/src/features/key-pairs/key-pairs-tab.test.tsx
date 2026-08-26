import { act, render, screen, waitFor, within } from "@testing-library/react"
import { StrictMode } from "react"
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

  test("loads public and private key files into their textareas", async () => {
    const user = userEvent.setup()
    render(
      <StrictMode>
        <KeyPairsTab resource={resource({ data: [] })} notify={notify} />
      </StrictMode>,
    )

    await user.click(screen.getByRole("button", { name: "New key pair" }))
    const dialog = await screen.findByRole("dialog")
    const publicFile = new File(["PUBLIC-FROM-FILE"], "id_rsa.pub", { type: "text/plain" })
    const privateFile = new File(["PRIVATE-FROM-FILE"], "id_rsa", { type: "text/plain" })

    await user.upload(within(dialog).getByLabelText("Select public key file"), publicFile)
    await user.upload(within(dialog).getByLabelText("Select private key file"), privateFile)

    await waitFor(() => {
      expect(within(dialog).getByLabelText("Public key")).toHaveValue("PUBLIC-FROM-FILE")
      expect(within(dialog).getByLabelText("Private key")).toHaveValue("PRIVATE-FROM-FILE")
    })
  })

  test("does not apply a late file read after clearing key material", async () => {
    const user = userEvent.setup()
    let resolveText: (text: string) => void = () => {}
    const textPromise = new Promise<string>(resolve => {
      resolveText = resolve
    })
    const file = new File(["LATE-PUBLIC-MATERIAL"], "id_rsa.pub", { type: "text/plain" })
    vi.spyOn(file, "text").mockReturnValue(textPromise)
    render(<KeyPairsTab resource={resource({ data: [] })} notify={notify} />)

    await user.click(screen.getByRole("button", { name: "New key pair" }))
    const dialog = await screen.findByRole("dialog")
    await user.upload(within(dialog).getByLabelText("Select public key file"), file)
    await user.click(within(dialog).getByRole("button", { name: "Clear public key" }))

    await act(async () => {
      resolveText("LATE-PUBLIC-MATERIAL")
      await textPromise
    })

    expect(within(dialog).getByLabelText("Public key")).toHaveValue("")
    expect(within(dialog).getByLabelText("Public key")).toBeDisabled()
  })

  test("ignores a late file read from an older file selection", async () => {
    const user = userEvent.setup()
    let resolveFirst: (text: string) => void = () => {}
    let resolveSecond: (text: string) => void = () => {}
    const firstText = new Promise<string>(resolve => {
      resolveFirst = resolve
    })
    const secondText = new Promise<string>(resolve => {
      resolveSecond = resolve
    })
    const firstFile = new File(["FIRST"], "first.pub", { type: "text/plain" })
    const secondFile = new File(["SECOND"], "second.pub", { type: "text/plain" })
    vi.spyOn(firstFile, "text").mockReturnValue(firstText)
    vi.spyOn(secondFile, "text").mockReturnValue(secondText)
    render(<KeyPairsTab resource={resource({ data: [] })} notify={notify} />)

    await user.click(screen.getByRole("button", { name: "New key pair" }))
    const dialog = await screen.findByRole("dialog")
    const fileInput = within(dialog).getByLabelText("Select public key file")
    await user.upload(fileInput, firstFile)
    await user.upload(fileInput, secondFile)

    await act(async () => {
      resolveSecond("SECOND")
      await secondText
      resolveFirst("FIRST")
      await firstText
    })

    expect(within(dialog).getByLabelText("Public key")).toHaveValue("SECOND")
  })

  test("ignores a late file read error after clearing key material", async () => {
    const user = userEvent.setup()
    let rejectText: (reason?: unknown) => void = () => {}
    const textPromise = new Promise<string>((_, reject) => {
      rejectText = reject
    })
    const file = new File(["LATE-PUBLIC-MATERIAL"], "id_rsa.pub", { type: "text/plain" })
    vi.spyOn(file, "text").mockReturnValue(textPromise)
    render(<KeyPairsTab resource={resource({ data: [] })} notify={notify} />)

    await user.click(screen.getByRole("button", { name: "New key pair" }))
    const dialog = await screen.findByRole("dialog")
    await user.upload(within(dialog).getByLabelText("Select public key file"), file)
    await user.click(within(dialog).getByRole("button", { name: "Clear public key" }))

    await act(async () => {
      rejectText(new Error("read failed"))
      await textPromise.catch(() => undefined)
    })

    expect(within(dialog).queryByRole("alert")).not.toBeInTheDocument()
  })

  test("reversibly clears key material and disables text and file inputs", async () => {
    const user = userEvent.setup()
    render(<KeyPairsTab resource={resource({ data: [] })} notify={notify} />)

    await user.click(screen.getByRole("button", { name: "New key pair" }))
    const dialog = await screen.findByRole("dialog")
    const publicKey = within(dialog).getByLabelText("Public key")
    await user.type(publicKey, "PUBLIC-MATERIAL")

    await user.click(within(dialog).getByRole("button", { name: "Clear public key" }))
    expect(publicKey).toBeDisabled()
    expect(within(dialog).getByLabelText("Select public key file")).toBeDisabled()
    expect(publicKey).toHaveValue("")

    await user.click(within(dialog).getByRole("button", { name: "Undo clear public key" }))
    expect(publicKey).toBeEnabled()
    expect(within(dialog).getByLabelText("Select public key file")).toBeEnabled()
    expect(publicKey).toHaveValue("PUBLIC-MATERIAL")
  })

  test("renders passphrase as a password input with a non-reversible clear", async () => {
    const user = userEvent.setup()
    render(<KeyPairsTab resource={resource({ data: [] })} notify={notify} />)

    await user.click(screen.getByRole("button", { name: "New key pair" }))
    const dialog = await screen.findByRole("dialog")
    const passphrase = within(dialog).getByLabelText("Private key passphrase")
    expect(passphrase).toHaveAttribute("type", "password")

    await user.type(passphrase, "secret")
    await user.click(within(dialog).getByRole("button", { name: "Clear private key passphrase" }))
    expect(passphrase).toHaveValue("")
    expect(passphrase).toBeEnabled()
    expect(within(dialog).queryByRole("button", { name: "Undo clear private key passphrase" })).not.toBeInTheDocument()
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

  test("ignores a stale vault response after reopening the same pair", async () => {
    const user = userEvent.setup()
    let resolveFirst: (value: KeyPairVault) => void = () => {}
    let resolveSecond: (value: KeyPairVault) => void = () => {}
    const firstVault = new Promise<KeyPairVault>(resolve => {
      resolveFirst = resolve
    })
    const secondVault = new Promise<KeyPairVault>(resolve => {
      resolveSecond = resolve
    })
    mockedAPI.getKeyPair.mockReturnValueOnce(firstVault).mockReturnValueOnce(secondVault)
    render(<KeyPairsTab resource={resource({ data: [keyPair(1, "prod")] })} notify={notify} />)

    await user.click(screen.getByRole("button", { name: "Edit prod" }))
    const firstDialog = await screen.findByRole("dialog")
    await user.click(within(firstDialog).getByRole("button", { name: "Cancel" }))
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument())

    await user.click(screen.getByRole("button", { name: "Edit prod" }))
    const secondDialog = await screen.findByRole("dialog")
    await act(async () => {
      resolveSecond(vault(1, "prod", { public_key: "NEW-PUBLIC" }))
      await secondVault
      resolveFirst(vault(1, "prod", { public_key: "OLD-PUBLIC" }))
      await firstVault
    })

    expect(await within(secondDialog).findByLabelText("Public key")).toHaveValue("NEW-PUBLIC")
  })

  test("closing the edit dialog discards a late vault response", async () => {
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
    expect(within(dialog).getByText("Loading vault…")).toBeInTheDocument()

    // Cancel while the vault GET is still pending; the dialog must close
    // and the late response must not reopen it or repopulate secret state.
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }))
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument())

    await act(async () => {
      resolveVault(vault(1, "prod"))
    })

    expect(screen.queryByRole("dialog")).not.toBeInTheDocument()
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
