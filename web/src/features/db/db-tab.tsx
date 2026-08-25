import { useRef, useState } from "react"
import { api } from "@/api/client"
import type { DBConnection, DBConnectionRequest, DependentsResponse, Group, SSHConnection } from "@/api/types"
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
import { DBForm } from "./db-form"

export interface DBTabProps {
  resource: ListResource<DBConnection>
  sshProfiles: readonly SSHConnection[]
  /** Groups backing the form selector. */
  groups: readonly Group[]
  notify: (message: string, kind: "success" | "error") => void
}

type FormDialogState = { mode: "create" } | { mode: "edit"; connection: DBConnection }

interface DeleteDialogState {
  target: DBConnection
  dependents: DependentsResponse | null
  loading: boolean
  error: string | null
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

/** Group display for one row: the name, (Ungrouped), or a Missing marker
 * for an externally corrupted nonzero reference. */
function groupCell(connection: DBConnection): string {
  if (connection.group_name) return connection.group_name
  if (connection.group_id === 0) return "(Ungrouped)"
  return `Missing group #${connection.group_id}`
}

/** SSH relationship display for one row: Direct, the profile name when
 * resolvable, or a visible Missing marker for a deleted profile. */
function sshCell(connection: DBConnection, profiles: readonly SSHConnection[]): string {
  if (connection.ssh_connection_id === 0) return "Direct"
  const profile = profiles.find(candidate => candidate.id === connection.ssh_connection_id)
  return profile ? profile.name : `Missing SSH #${connection.ssh_connection_id}`
}

export function DBTab({ resource, sshProfiles, groups, notify }: DBTabProps) {
  const [formDialog, setFormDialog] = useState<FormDialogState | null>(null)
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
    setFormDialog({ mode: "create" })
  }

  const openEdit = (connection: DBConnection, trigger: HTMLElement) => {
    lastTriggerRef.current = trigger
    setFormError(null)
    setFormDialog({ mode: "edit", connection })
  }

  const handleSubmit = async (request: DBConnectionRequest) => {
    if (!formDialog) return
    setPending(true)
    setFormError(null)
    try {
      if (formDialog.mode === "edit") {
        await api.updateDB(formDialog.connection.id, request)
      } else {
        await api.createDB(request)
      }
      await resource.reload()
      setFormDialog(null)
      if (formDialog.mode === "edit") {
        notify(`Updated database connection "${request.name}".`, "success")
      } else {
        notify(`Created database connection "${request.name}".`, "success")
      }
    } catch (error) {
      setFormError(errorMessage(error))
    } finally {
      setPending(false)
    }
  }

  const requestDelete = async (connection: DBConnection, trigger: HTMLElement) => {
    lastTriggerRef.current = trigger
    setDeleteError(null)
    setDeleteDialog({ target: connection, dependents: null, loading: true, error: null })
    try {
      const dependents = await api.dbDependents(connection.id)
      setDeleteDialog({ target: connection, dependents, loading: false, error: null })
    } catch (error) {
      setDeleteDialog({ target: connection, dependents: null, loading: false, error: errorMessage(error) })
    }
  }

  const confirmDelete = async () => {
    if (!deleteDialog) return
    setDeletePending(true)
    setDeleteError(null)
    try {
      await api.deleteDB(deleteDialog.target.id)
      await resource.reload()
      setDeleteDialog(null)
      notify(`Deleted database connection "${deleteDialog.target.name}".`, "success")
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

  return (
    <div className="p-4">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-lg font-semibold">Database connections</h2>
        <Button type="button" onClick={event => openCreate(event.currentTarget)}>
          New database
        </Button>
      </div>

      {resource.loading && <p className="text-sm text-muted-foreground">Loading…</p>}
      {resource.error && (
        <ResourceError
          error={resource.error}
          onRetry={() => void resource.reload()}
          label="database connections"
        />
      )}
      {!resource.loading && !resource.error && resource.data.length === 0 && (
        <p className="text-sm text-muted-foreground">No database connections yet.</p>
      )}
      {!resource.loading && !resource.error && resource.data.length > 0 && (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Group</TableHead>
              <TableHead>Host</TableHead>
              <TableHead>Username</TableHead>
              <TableHead>Auth</TableHead>
              <TableHead>Database</TableHead>
              <TableHead>SSH connection</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {resource.data.map(connection => (
              <TableRow key={connection.id}>
                <TableCell className="font-medium">{connection.name}</TableCell>
                <TableCell>
                  {connection.group_id === 0 && !connection.group_name ? (
                    <span className="text-sm text-muted-foreground">(Ungrouped)</span>
                  ) : (
                    groupCell(connection)
                  )}
                </TableCell>
                <TableCell>
                  {connection.host}:{connection.port}
                </TableCell>
                <TableCell>{connection.username}</TableCell>
                <TableCell>
                  {connection.has_password ? (
                    <Badge variant="secondary">Password</Badge>
                  ) : (
                    <span className="text-sm text-muted-foreground">None</span>
                  )}
                </TableCell>
                <TableCell>{connection.database}</TableCell>
                <TableCell>{sshCell(connection, sshProfiles)}</TableCell>
                <TableCell className="text-right">
                  <div className="flex justify-end gap-1">
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      aria-label={`Edit ${connection.name}`}
                      onClick={event => openEdit(connection, event.currentTarget)}
                    >
                      Edit
                    </Button>
                    <Button
                      type="button"
                      variant="destructive"
                      size="sm"
                      aria-label={`Delete ${connection.name}`}
                      onClick={event => void requestDelete(connection, event.currentTarget)}
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
              {formDialog?.mode === "edit" ? `Edit ${formDialog.connection.name}` : "New database connection"}
            </DialogTitle>
            <DialogDescription>
              Secret fields are never shown; leave them blank to keep stored values.
            </DialogDescription>
          </DialogHeader>
          {formDialog && (
            <DBForm
              key={formDialog.mode === "edit" ? formDialog.connection.id : "new"}
              connection={formDialog.mode === "edit" ? formDialog.connection : null}
              sshProfiles={sshProfiles}
              groups={groups}
              pending={pending}
              error={formError}
              onSubmit={request => void handleSubmit(request)}
              onCancel={() => setFormDialog(null)}
            />
          )}
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
            <DialogTitle>Delete database connection</DialogTitle>
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
                    These connections reference it and will become invalid:
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
