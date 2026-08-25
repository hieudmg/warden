import { useRef, useState, type FormEvent } from "react"
import { api } from "@/api/client"
import type { DependentsResponse, Group } from "@/api/types"
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
import type { ListResource } from "@/hooks/use-list-resource"

export interface GroupsTabProps {
  resource: ListResource<Group>
  notify: (message: string, kind: "success" | "error") => void
}

type FormDialogState = { mode: "create" } | { mode: "edit"; group: Group }

interface DeleteDialogState {
  target: Group
  dependents: DependentsResponse | null
  loading: boolean
  error: string | null
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

/** Deterministic UTC timestamp label for a group's server-generated time. */
function formatTimestamp(iso: string): string {
  const date = new Date(iso)
  const pad = (n: number) => String(n).padStart(2, "0")
  return `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())} ${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())} UTC`
}

export function GroupsTab({ resource, notify }: GroupsTabProps) {
  const [query, setQuery] = useState("")
  const [formDialog, setFormDialog] = useState<FormDialogState | null>(null)
  const [name, setName] = useState("")
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

  const openCreate = (trigger: HTMLElement) => {
    lastTriggerRef.current = trigger
    setFormError(null)
    setName("")
    setFormDialog({ mode: "create" })
  }

  const openEdit = (group: Group, trigger: HTMLElement) => {
    lastTriggerRef.current = trigger
    setFormError(null)
    setName(group.name)
    setFormDialog({ mode: "edit", group })
  }

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault()
    if (!formDialog) return
    setPending(true)
    setFormError(null)
    try {
      if (formDialog.mode === "edit") {
        await api.updateGroup(formDialog.group.id, { name })
      } else {
        await api.createGroup({ name })
      }
      await resource.reload()
      setFormDialog(null)
      if (formDialog.mode === "edit") {
        notify(`Updated group "${name}".`, "success")
      } else {
        notify(`Created group "${name}".`, "success")
      }
    } catch (error) {
      setFormError(errorMessage(error))
    } finally {
      setPending(false)
    }
  }

  const requestDelete = async (group: Group, trigger: HTMLElement) => {
    lastTriggerRef.current = trigger
    setDeleteError(null)
    setDeleteDialog({ target: group, dependents: null, loading: true, error: null })
    try {
      const dependents = await api.groupDependents(group.id)
      setDeleteDialog({ target: group, dependents, loading: false, error: null })
    } catch (error) {
      setDeleteDialog({ target: group, dependents: null, loading: false, error: errorMessage(error) })
    }
  }

  const confirmDelete = async () => {
    if (!deleteDialog) return
    setDeletePending(true)
    setDeleteError(null)
    try {
      await api.deleteGroup(deleteDialog.target.id)
      await resource.reload()
      setDeleteDialog(null)
      notify(`Deleted group "${deleteDialog.target.name}".`, "success")
    } catch (error) {
      setDeleteError(errorMessage(error))
    } finally {
      setDeletePending(false)
    }
  }

  const dependents = deleteDialog?.dependents
  const hasDependents =
    dependents !== null && dependents !== undefined &&
    (dependents.ssh.length > 0 || dependents.db.length > 0)

  const needle = query.trim().toLowerCase()
  const filtered =
    needle === ""
      ? resource.data
      : resource.data.filter(group => group.name.toLowerCase().includes(needle))

  return (
    <div className="p-4">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-lg font-semibold">Groups</h2>
        <Button type="button" onClick={event => openCreate(event.currentTarget)}>
          New group
        </Button>
      </div>

      {resource.loading && <p className="text-sm text-muted-foreground">Loading…</p>}
      {resource.error && (
        <ResourceError
          error={resource.error}
          onRetry={() => void resource.reload()}
          label="groups"
        />
      )}
      {!resource.loading && !resource.error && resource.data.length === 0 && (
        <p className="text-sm text-muted-foreground">No groups yet.</p>
      )}
      {!resource.loading && !resource.error && resource.data.length > 0 && (
        <div className="space-y-3">
          <div className="grid gap-1.5 max-w-sm">
            <Label htmlFor="groups-search">Search groups</Label>
            <Input
              id="groups-search"
              value={query}
              onChange={event => setQuery(event.target.value)}
              placeholder="Filter by name"
            />
          </div>
          {filtered.length === 0 ? (
            <p className="text-sm text-muted-foreground">No groups match your search.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Used by</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead>Updated</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.map(group => (
                  <TableRow key={group.id}>
                    <TableCell className="font-medium">{group.name}</TableCell>
                    <TableCell>
                      SSH {group.ssh_connection_count} · DB {group.db_connection_count}
                    </TableCell>
                    <TableCell>{formatTimestamp(group.created_at)}</TableCell>
                    <TableCell>{formatTimestamp(group.updated_at)}</TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-1">
                        <Button
                          type="button"
                          variant="outline"
                          size="sm"
                          aria-label={`Edit ${group.name}`}
                          onClick={event => openEdit(group, event.currentTarget)}
                        >
                          Edit
                        </Button>
                        <Button
                          type="button"
                          variant="destructive"
                          size="sm"
                          aria-label={`Delete ${group.name}`}
                          onClick={event => void requestDelete(group, event.currentTarget)}
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
          if (!open && !pending) setFormDialog(null)
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
              {formDialog?.mode === "edit" ? `Edit ${formDialog.group.name}` : "New group"}
            </DialogTitle>
            <DialogDescription>
              Groups are shared labels for SSH and database connections.
            </DialogDescription>
          </DialogHeader>
          <form onSubmit={event => void handleSubmit(event)} autoComplete="off" className="grid gap-3">
            <div className="grid gap-1.5">
              <Label htmlFor="group-name">Name</Label>
              <Input
                id="group-name"
                value={name}
                onChange={event => setName(event.target.value)}
                required
              />
            </div>
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
              <Button type="submit" disabled={pending}>
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
            <DialogTitle>Delete group</DialogTitle>
            <DialogDescription>
              {deleteDialog?.loading
                ? "Checking for dependents…"
                : deleteDialog?.error
                  ? "Unable to check for dependents."
                  : `This will permanently delete "${deleteDialog?.target.name}".`}
            </DialogDescription>
          </DialogHeader>
          {deleteDialog && !deleteDialog.loading && !deleteDialog.error && (
            <>
              {hasDependents ? (
                <div className="text-sm">
                  <p className="text-destructive">
                    These connections reference it and will become ungrouped:
                  </p>
                  <ul className="mt-1 list-inside list-disc">
                    {dependents!.ssh.map(dependent => (
                      <li key={`ssh-${dependent.id}`}>{dependent.name} (SSH)</li>
                    ))}
                    {dependents!.db.map(dependent => (
                      <li key={`db-${dependent.id}`}>{dependent.name} (Database)</li>
                    ))}
                  </ul>
                </div>
              ) : (
                <p className="text-sm text-muted-foreground">
                  No other connections reference it.
                </p>
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
              {!deleteDialog.error && (
                <Button
                  type="button"
                  variant="destructive"
                  onClick={() => void confirmDelete()}
                  disabled={deletePending}
                >
                  {deletePending ? "Deleting" : "Delete"}
                </Button>
              )}
            </DialogFooter>
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}
