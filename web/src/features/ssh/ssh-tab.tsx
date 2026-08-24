import { useState } from "react"
import { api } from "@/api/client"
import type { DependentsResponse, SSHConnection, SSHConnectionRequest } from "@/api/types"
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

/** Jump-route display labels for one row; self-references are visibly marked. */
function jumpRouteLabels(connection: SSHConnection, profiles: readonly SSHConnection[]): string {
  const ids = parseJumpRoute(connection.jump_connection_ids)
  if (ids.length === 0) return "—"
  return ids.map(id => jumpLabel(id, profiles, connection.id)).join(", ")
}

export function SSHTab({ resource, notify }: SSHTabProps) {
  const [formDialog, setFormDialog] = useState<FormDialogState | null>(null)
  const [pending, setPending] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)
  const [deleteDialog, setDeleteDialog] = useState<DeleteDialogState | null>(null)
  const [deletePending, setDeletePending] = useState(false)
  const [deleteError, setDeleteError] = useState<string | null>(null)

  const openCreate = () => {
    setFormError(null)
    setFormDialog({ mode: "create" })
  }

  const openEdit = (connection: SSHConnection) => {
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
        notify(`Updated SSH connection "${request.name}".`, "success")
      } else {
        await api.createSSH(request)
        notify(`Created SSH connection "${request.name}".`, "success")
      }
      setFormDialog(null)
      await resource.reload()
    } catch (error) {
      setFormError(errorMessage(error))
    } finally {
      setPending(false)
    }
  }

  const requestDelete = async (connection: SSHConnection) => {
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
      setDeleteDialog(null)
      await resource.reload()
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
        <Button type="button" onClick={openCreate}>
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
                      onClick={() => openEdit(connection)}
                    >
                      Edit
                    </Button>
                    <Button
                      type="button"
                      variant="destructive"
                      size="sm"
                      aria-label={`Delete ${connection.name}`}
                      onClick={() => void requestDelete(connection)}
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
        <DialogContent>
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
        <DialogContent>
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
