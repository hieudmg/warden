import { useRef, useState } from "react"
import { api } from "@/api/client"
import type { DependentsResponse, Group, SSHConnection, SSHConnectionRequest } from "@/api/types"
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
import { jumpLabel, parseJumpRoute } from "./jump-route"
import { SSHForm } from "./ssh-form"

export interface SSHTabProps {
  resource: ListResource<SSHConnection>
  /** Groups backing the form selector. */
  groups: readonly Group[]
  notify: (message: string, kind: "success" | "error") => void
}

type FormDialogState = { mode: "create" } | { mode: "edit"; connection: SSHConnection }

interface DeleteDialogState {
  target: SSHConnection
  dependents: DependentsResponse | null
  loading: boolean
  error: string | null
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

/** Group display for one row: the name, (Ungrouped), or a Missing marker
 * for an externally corrupted nonzero reference. */
function groupCell(connection: SSHConnection): string {
  if (connection.group_name) return connection.group_name
  if (connection.group_id === 0) return "(Ungrouped)"
  return `Missing group #${connection.group_id}`
}

/** Jump-route display labels for one row; self-references are visibly marked. */
function jumpRouteLabels(connection: SSHConnection, profiles: readonly SSHConnection[]): string {
  const ids = parseJumpRoute(connection.jump_connection_ids)
  if (ids.length === 0) return "—"
  return ids.map(id => jumpLabel(id, profiles, connection.id)).join(", ")
}

export function SSHTab({ resource, groups, notify }: SSHTabProps) {
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

  const openEdit = (connection: SSHConnection, trigger: HTMLElement) => {
    lastTriggerRef.current = trigger
    setFormError(null)
    setFormDialog({ mode: "edit", connection })
  }

  const handleSubmit = async (request: SSHConnectionRequest) => {
    if (!formDialog) return
    setPending(true)
    setFormError(null)
    try {
      if (formDialog.mode === "edit") {
        await api.updateSSH(formDialog.connection.id, request)
      } else {
        await api.createSSH(request)
      }
      await resource.reload()
      setFormDialog(null)
      if (formDialog.mode === "edit") {
        notify(`Updated SSH connection "${request.name}".`, "success")
      } else {
        notify(`Created SSH connection "${request.name}".`, "success")
      }
    } catch (error) {
      setFormError(errorMessage(error))
    } finally {
      setPending(false)
    }
  }

  const requestDelete = async (connection: SSHConnection, trigger: HTMLElement) => {
    lastTriggerRef.current = trigger
    setDeleteError(null)
    setDeleteDialog({ target: connection, dependents: null, loading: true, error: null })
    try {
      const dependents = await api.sshDependents(connection.id)
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
      await api.deleteSSH(deleteDialog.target.id)
      await resource.reload()
      setDeleteDialog(null)
      notify(`Deleted SSH connection "${deleteDialog.target.name}".`, "success")
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
        <h2 className="text-lg font-semibold">SSH connections</h2>
        <Button type="button" onClick={event => openCreate(event.currentTarget)}>
          New connection
        </Button>
      </div>

      {resource.loading && <p className="text-sm text-muted-foreground">Loading…</p>}
      {resource.error && (
        <ResourceError
          error={resource.error}
          onRetry={() => void resource.reload()}
          label="SSH connections"
        />
      )}
      {!resource.loading && !resource.error && resource.data.length === 0 && (
        <p className="text-sm text-muted-foreground">No SSH connections yet.</p>
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
              <TableHead>Proxy</TableHead>
              <TableHead>Jump route</TableHead>
              <TableHead>Default dir</TableHead>
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
                  <div className="flex flex-wrap gap-1">
                    {connection.has_password && <Badge variant="secondary">Password</Badge>}
                    {connection.has_private_key && <Badge variant="secondary">Private key</Badge>}
                    {connection.has_private_key_passphrase && (
                      <Badge variant="secondary">Key passphrase</Badge>
                    )}
                    {connection.has_proxy_password && <Badge variant="secondary">Proxy password</Badge>}
                    {!connection.has_password &&
                      !connection.has_private_key &&
                      !connection.has_private_key_passphrase &&
                      !connection.has_proxy_password && (
                        <span className="text-sm text-muted-foreground">None</span>
                      )}
                  </div>
                </TableCell>
                <TableCell>
                  {connection.proxy_host
                    ? `${connection.proxy_host}:${connection.proxy_port}`
                    : "—"}
                </TableCell>
                <TableCell>{jumpRouteLabels(connection, resource.data)}</TableCell>
                <TableCell>{connection.default_dir || "—"}</TableCell>
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
              {formDialog?.mode === "edit" ? `Edit ${formDialog.connection.name}` : "New SSH connection"}
            </DialogTitle>
            <DialogDescription>
              Secret fields are never shown; leave them blank to keep stored values.
            </DialogDescription>
          </DialogHeader>
          {formDialog && (
            <SSHForm
              key={formDialog.mode === "edit" ? formDialog.connection.id : "new"}
              connection={formDialog.mode === "edit" ? formDialog.connection : null}
              profiles={resource.data}
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
            <DialogTitle>Delete SSH connection</DialogTitle>
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
