import { useRef, useState, type FormEvent } from "react"
import { api } from "@/api/client"
import type {
  DependentsResponse,
  KeyPairRequest,
  KeyPairSummary,
  KeyPairVault,
} from "@/api/types"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { ResourceError } from "@/components/resource-error"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Textarea } from "@/components/ui/textarea"
import type { ListResource } from "@/hooks/use-list-resource"

export interface KeyPairsTabProps {
  resource: ListResource<KeyPairSummary>
  notify: (message: string, kind: "success" | "error") => void
}

type FormDialogState =
  | { mode: "create" }
  | { mode: "edit"; pair: KeyPairSummary; vault: KeyPairVault | null; vaultError: string | null }

interface DeleteDialogState {
  target: KeyPairSummary
  dependents: DependentsResponse | null
  loading: boolean
  error: string | null
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

/** Deterministic UTC timestamp label for a pair's server-generated time. */
function formatTimestamp(iso: string): string {
  const date = new Date(iso)
  const pad = (n: number) => String(n).padStart(2, "0")
  return `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())} ${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())} UTC`
}

/**
 * Edit serialization: an untouched blank field must not clear stored
 * material, so unchanged values serialize as null (omitted → server keeps
 * the stored value). A user edit — including a deliberate clear to "" —
 * serializes as the new value.
 */
function changedSecret(current: string, original: string): string | null {
  return current === original ? null : current
}

export function KeyPairsTab({ resource, notify }: KeyPairsTabProps) {
  const [query, setQuery] = useState("")
  const [formDialog, setFormDialog] = useState<FormDialogState | null>(null)
  const [name, setName] = useState("")
  const [publicKey, setPublicKey] = useState("")
  const [privateKey, setPrivateKey] = useState("")
  const [passphrase, setPassphrase] = useState("")
  const [pending, setPending] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)
  const [deleteDialog, setDeleteDialog] = useState<DeleteDialogState | null>(null)
  const [deletePending, setDeletePending] = useState(false)
  const [deleteError, setDeleteError] = useState<string | null>(null)

  // Controlled dialogs have no DialogTrigger, so Radix cannot restore focus
  // to the opener on close; capture the trigger element and restore it via
  // the Dialog primitive's onCloseAutoFocus hook (spec: focus returns to the
  // trigger on close).
  const lastTriggerRef = useRef<HTMLElement | null>(null)
  // Guards vault GET resolution against overwriting a newer dialog (raw
  // values are kept only in edit dialog state, never in table state).
  const editIDRef = useRef<number | null>(null)

  const openCreate = (trigger: HTMLElement) => {
    lastTriggerRef.current = trigger
    editIDRef.current = null
    setFormError(null)
    setName("")
    setPublicKey("")
    setPrivateKey("")
    setPassphrase("")
    setFormDialog({ mode: "create" })
  }

  const openEdit = (pair: KeyPairSummary, trigger: HTMLElement) => {
    lastTriggerRef.current = trigger
    editIDRef.current = pair.id
    setFormError(null)
    setName(pair.name)
    setPublicKey("")
    setPrivateKey("")
    setPassphrase("")
    setFormDialog({ mode: "edit", pair, vault: null, vaultError: null })
    void loadVault(pair)
  }

  const loadVault = async (pair: KeyPairSummary) => {
    try {
      const vault = await api.getKeyPair(pair.id)
      if (editIDRef.current === pair.id) {
        setFormDialog({ mode: "edit", pair, vault, vaultError: null })
        setPublicKey(vault.public_key)
        setPrivateKey(vault.private_key)
        setPassphrase(vault.private_key_passphrase)
      }
    } catch (error) {
      if (editIDRef.current === pair.id) {
        setFormDialog({ mode: "edit", pair, vault: null, vaultError: errorMessage(error) })
      }
    }
  }

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault()
    if (!formDialog) return
    if (formDialog.mode === "edit" && formDialog.vault === null) return
    setPending(true)
    setFormError(null)
    let createdOrUpdated = ""
    try {
      if (formDialog.mode === "edit") {
        const vault = formDialog.vault
        if (vault === null) return
        const request: KeyPairRequest = {
          name,
          public_key: changedSecret(publicKey, vault.public_key),
          private_key: changedSecret(privateKey, vault.private_key),
          private_key_passphrase: changedSecret(passphrase, vault.private_key_passphrase),
        }
        await api.updateKeyPair(formDialog.pair.id, request)
        createdOrUpdated = "Updated"
      } else {
        const request: KeyPairRequest = {
          name,
          public_key: publicKey === "" ? null : publicKey,
          private_key: privateKey === "" ? null : privateKey,
          private_key_passphrase: passphrase === "" ? null : passphrase,
        }
        await api.createKeyPair(request)
        createdOrUpdated = "Created"
      }
      await resource.reload()
      setFormDialog(null)
      editIDRef.current = null
      notify(`${createdOrUpdated} key pair "${name}".`, "success")
    } catch (error) {
      setFormError(errorMessage(error))
    } finally {
      setPending(false)
    }
  }

  const requestDelete = async (pair: KeyPairSummary, trigger: HTMLElement) => {
    lastTriggerRef.current = trigger
    setDeleteError(null)
    setDeleteDialog({ target: pair, dependents: null, loading: true, error: null })
    try {
      const dependents = await api.keyPairDependents(pair.id)
      setDeleteDialog({ target: pair, dependents, loading: false, error: null })
    } catch (error) {
      setDeleteDialog({ target: pair, dependents: null, loading: false, error: errorMessage(error) })
    }
  }

  const confirmDelete = async () => {
    if (!deleteDialog) return
    setDeletePending(true)
    setDeleteError(null)
    try {
      await api.deleteKeyPair(deleteDialog.target.id)
      await resource.reload()
      setDeleteDialog(null)
      notify(`Deleted key pair "${deleteDialog.target.name}".`, "success")
    } catch (error) {
      setDeleteError(errorMessage(error))
    } finally {
      setDeletePending(false)
    }
  }

  const dependents = deleteDialog?.dependents
  const hasDependents = dependents !== null && dependents !== undefined && dependents.ssh.length > 0

  const needle = query.trim().toLowerCase()
  const filtered =
    needle === ""
      ? resource.data
      : resource.data.filter(pair => pair.name.toLowerCase().includes(needle))

  const editing = formDialog?.mode === "edit"
  const vaultLoaded = !editing || formDialog.vault !== null
  const showSecretFields = formDialog !== null && vaultLoaded

  return (
    <div className="p-4">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-lg font-semibold">Key pairs</h2>
        <Button type="button" onClick={event => openCreate(event.currentTarget)}>
          New key pair
        </Button>
      </div>

      {resource.loading && <p className="text-sm text-muted-foreground">Loading…</p>}
      {resource.error && (
        <ResourceError
          error={resource.error}
          onRetry={() => void resource.reload()}
          label="key pairs"
        />
      )}
      {!resource.loading && !resource.error && resource.data.length === 0 && (
        <p className="text-sm text-muted-foreground">No key pairs yet.</p>
      )}
      {!resource.loading && !resource.error && resource.data.length > 0 && (
        <div className="space-y-3">
          <div className="grid gap-1.5 max-w-sm">
            <Label htmlFor="key-pairs-search">Search key pairs</Label>
            <Input
              id="key-pairs-search"
              value={query}
              onChange={event => setQuery(event.target.value)}
              placeholder="Filter by name"
            />
          </div>
          {filtered.length === 0 ? (
            <p className="text-sm text-muted-foreground">No key pairs match your search.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Credentials</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead>Updated</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.map(pair => (
                  <TableRow key={pair.id}>
                    <TableCell className="font-medium">{pair.name}</TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {pair.has_public_key && <Badge variant="secondary">Public key</Badge>}
                        {pair.has_private_key && <Badge variant="secondary">Private key</Badge>}
                        {pair.has_private_key_passphrase && <Badge variant="secondary">Passphrase</Badge>}
                        {!pair.has_public_key &&
                          !pair.has_private_key &&
                          !pair.has_private_key_passphrase && (
                            <span className="text-sm text-muted-foreground">None</span>
                          )}
                      </div>
                    </TableCell>
                    <TableCell>{formatTimestamp(pair.created_at)}</TableCell>
                    <TableCell>{formatTimestamp(pair.updated_at)}</TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-1">
                        <Button
                          type="button"
                          variant="outline"
                          size="sm"
                          aria-label={`Edit ${pair.name}`}
                          onClick={event => openEdit(pair, event.currentTarget)}
                        >
                          Edit
                        </Button>
                        <Button
                          type="button"
                          variant="destructive"
                          size="sm"
                          aria-label={`Delete ${pair.name}`}
                          onClick={event => void requestDelete(pair, event.currentTarget)}
                        >
                          Delete
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </div>
      )}

      <Dialog
        open={formDialog !== null}
        onOpenChange={open => {
          if (!open && !pending) {
            editIDRef.current = null
            setFormDialog(null)
          }
        }}
      >
        <DialogContent
          onCloseAutoFocus={event => {
            event.preventDefault()
            lastTriggerRef.current?.focus()
          }}
        >
          <DialogHeader>
            <DialogTitle>
              {formDialog?.mode === "edit" ? `Edit ${formDialog.pair.name}` : "New key pair"}
            </DialogTitle>
            <DialogDescription>
              Key pairs are shared across SSH connections; editing a pair changes every connection
              that uses it.
            </DialogDescription>
          </DialogHeader>
          <form onSubmit={event => void handleSubmit(event)} autoComplete="off" className="grid gap-3">
            <div className="grid gap-1.5">
              <Label htmlFor="key-pair-name">Name</Label>
              <Input
                id="key-pair-name"
                value={name}
                onChange={event => setName(event.target.value)}
                required
              />
            </div>
            {formDialog?.mode === "edit" && formDialog.vault === null && !formDialog.vaultError && (
              <p className="text-sm text-muted-foreground">Loading vault…</p>
            )}
            {formDialog?.mode === "edit" && formDialog.vaultError && (
              <p role="alert" className="text-sm text-destructive">
                Unable to load vault: {formDialog.vaultError}
              </p>
            )}
            {showSecretFields && (
              <>
                <div className="grid gap-1.5">
                  <Label htmlFor="key-pair-public-key">Public key</Label>
                  <Textarea
                    id="key-pair-public-key"
                    value={publicKey}
                    onChange={event => setPublicKey(event.target.value)}
                    autoComplete="off"
                    rows={3}
                  />
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    className="justify-self-start"
                    onClick={() => setPublicKey("")}
                  >
                    Clear public key
                  </Button>
                </div>
                <div className="grid gap-1.5">
                  <Label htmlFor="key-pair-private-key">Private key</Label>
                  <Textarea
                    id="key-pair-private-key"
                    value={privateKey}
                    onChange={event => setPrivateKey(event.target.value)}
                    autoComplete="off"
                    rows={3}
                  />
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    className="justify-self-start"
                    onClick={() => setPrivateKey("")}
                  >
                    Clear private key
                  </Button>
                </div>
                <div className="grid gap-1.5">
                  <Label htmlFor="key-pair-passphrase">Private key passphrase</Label>
                  <Textarea
                    id="key-pair-passphrase"
                    value={passphrase}
                    onChange={event => setPassphrase(event.target.value)}
                    autoComplete="off"
                    rows={2}
                  />
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    className="justify-self-start"
                    onClick={() => setPassphrase("")}
                  >
                    Clear private key passphrase
                  </Button>
                </div>
              </>
            )}
            {formError && (
              <p role="alert" className="text-sm text-destructive">
                {formError}
              </p>
            )}
            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => setFormDialog(null)}
                disabled={pending}
              >
                Cancel
              </Button>
              <Button
                type="submit"
                disabled={pending || (formDialog?.mode === "edit" && formDialog.vault === null)}
              >
                {pending ? "Saving" : "Save"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <Dialog
        open={deleteDialog !== null}
        onOpenChange={open => {
          if (!open && !deletePending) setDeleteDialog(null)
        }}
      >
        <DialogContent
          onCloseAutoFocus={event => {
            event.preventDefault()
            lastTriggerRef.current?.focus()
          }}
        >
          <DialogHeader>
            <DialogTitle>Delete key pair</DialogTitle>
            <DialogDescription>
              {deleteDialog?.loading
                ? "Checking for dependents…"
                : `This will permanently delete "${deleteDialog?.target.name}".`}
            </DialogDescription>
          </DialogHeader>
          {deleteDialog && !deleteDialog.loading && (
            <>
              {deleteDialog.error ? (
                <p role="alert" className="text-sm text-destructive">
                  Unable to check for dependents: {deleteDialog.error}. You can still delete this key
                  pair.
                </p>
              ) : hasDependents ? (
                <div className="text-sm">
                  <p className="text-destructive">
                    These SSH connections reference it and will fail to resolve until updated:
                  </p>
                  <ul className="mt-1 list-inside list-disc">
                    {dependents!.ssh.map(dependent => (
                      <li key={`ssh-${dependent.id}`}>{dependent.name} (SSH)</li>
                    ))}
                  </ul>
                </div>
              ) : (
                <p className="text-sm text-muted-foreground">No SSH connections reference it.</p>
              )}
              {deleteError && (
                <p role="alert" className="text-sm text-destructive">
                  {deleteError}
                </p>
              )}
            </>
          )}
          {deleteDialog && !deleteDialog.loading && (
            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => setDeleteDialog(null)}
                disabled={deletePending}
              >
                Cancel
              </Button>
              <Button
                type="button"
                variant="destructive"
                onClick={() => void confirmDelete()}
                disabled={deletePending}
              >
                {deletePending ? "Deleting" : "Delete"}
              </Button>
            </DialogFooter>
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}
