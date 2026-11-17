import { useRef, useState } from "react"
import { api } from "@/api/client"
import type { Group, HTTPConnection, HTTPConnectionRequest } from "@/api/types"
import { ResourceError } from "@/components/resource-error"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { groupedTableRows } from "@/features/grouped-table"
import type { ListResource } from "@/hooks/use-list-resource"
import { HTTPForm } from "./http-form"

interface HTTPTabProps {
  resource: ListResource<HTTPConnection>
  groups: readonly Group[]
  notify: (message: string, kind: "success" | "error") => void
}
type FormDialogState = { mode: "create" } | { mode: "edit"; connection: HTTPConnection }
function errorMessage(error: unknown): string { return error instanceof Error ? error.message : String(error) }
const authLabels = { bearer: "Bearer", x_api_key: "X-API-Key", basic: "Basic" }

export function HTTPTab({ resource, groups, notify }: HTTPTabProps) {
  const [formDialog, setFormDialog] = useState<FormDialogState | null>(null)
  const [pending, setPending] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<HTTPConnection | null>(null)
  const [deletePending, setDeletePending] = useState(false)
  const [deleteError, setDeleteError] = useState<string | null>(null)
  const [archivePending, setArchivePending] = useState<number | null>(null)
  const lastTriggerRef = useRef<HTMLElement | null>(null)
  const openForm = (state: FormDialogState, trigger: HTMLElement) => {
    lastTriggerRef.current = trigger
    setFormError(null)
    setFormDialog(state)
  }
  const submit = async (request: HTTPConnectionRequest) => {
    if (!formDialog || pending) return
    setPending(true)
    setFormError(null)
    try {
      if (formDialog.mode === "edit") await api.updateHTTP(formDialog.connection.id, request)
      else await api.createHTTP(request)
      await resource.reload()
      setFormDialog(null)
      notify(`${formDialog.mode === "edit" ? "Updated" : "Created"} HTTP connection "${request.name}".`, "success")
    } catch (error) { setFormError(errorMessage(error)) }
    finally { setPending(false) }
  }
  const confirmDelete = async () => {
    if (!deleteTarget || deletePending) return
    setDeletePending(true)
    setDeleteError(null)
    try {
      await api.deleteHTTP(deleteTarget.id)
      await resource.reload()
      setDeleteTarget(null)
      notify(`Deleted HTTP connection "${deleteTarget.name}".`, "success")
    } catch (error) { setDeleteError(errorMessage(error)) }
    finally { setDeletePending(false) }
  }
  const archive = async (connection: HTTPConnection) => {
    if (archivePending !== null) return
    setArchivePending(connection.id)
    try {
      await api.archiveHTTP(connection.id, !connection.archived)
      await resource.reload()
      notify(`${connection.archived ? "Restored" : "Archived"} HTTP connection "${connection.name}".`, "success")
    } catch (error) { notify(errorMessage(error), "error") }
    finally { setArchivePending(null) }
  }
  const rows = groupedTableRows(resource.data)
  const active = rows.filter(row => !row.item.archived)
  const archived = rows.filter(row => row.item.archived)
  const renderRow = ({ item: connection, groupLabel, backgroundClass }: typeof rows[number]) => (
    <TableRow key={connection.id} className={backgroundClass}>
      <TableCell>{groupLabel}</TableCell>
      <TableCell className="font-medium">{connection.name}</TableCell>
      <TableCell className="max-w-xs whitespace-pre-wrap">{connection.note || "—"}</TableCell>
      <TableCell>{connection.origin}</TableCell>
      <TableCell>{authLabels[connection.auth_type]}</TableCell>
      <TableCell>{connection.auth_type === "basic"
        ? `Username ${connection.has_username ? "saved" : "missing"} · Password ${connection.has_password ? "saved" : "missing"}`
        : `Credential ${connection.has_credential ? "saved" : "missing"}`}</TableCell>
      <TableCell className="text-right">
        <div className="flex justify-end gap-1">
          <Button type="button" variant="outline" size="sm" aria-label={`Edit ${connection.name}`} onClick={event => openForm({ mode: "edit", connection }, event.currentTarget)}>Edit</Button>
          <Button type="button" variant="outline" size="sm" disabled={archivePending !== null} aria-label={`${connection.archived ? "Restore" : "Archive"} ${connection.name}`} onClick={() => void archive(connection)}>{connection.archived ? "Restore" : "Archive"}</Button>
          <Button type="button" variant="destructive" size="sm" aria-label={`Delete ${connection.name}`} onClick={event => {
            lastTriggerRef.current = event.currentTarget
            setDeleteError(null)
            setDeleteTarget(connection)
          }}>Delete</Button>
        </div>
      </TableCell>
    </TableRow>
  )
  const restoreFocus = (event: Event) => {
    event.preventDefault()
    lastTriggerRef.current?.focus()
  }

  return (
    <div className="p-4">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-lg font-semibold">HTTP connections</h2>
        <Button type="button" onClick={event => openForm({ mode: "create" }, event.currentTarget)}>New HTTP connection</Button>
      </div>
      <p className="mb-3 text-sm text-muted-foreground">Manage named origins and server-held credentials here; run requests with warden http. HTTP transport is unencrypted and can expose credentials. HTTPS verifies certificates.</p>
      {resource.loading && <p className="text-sm text-muted-foreground">Loading…</p>}
      {resource.error && <ResourceError error={resource.error} onRetry={() => void resource.reload()} label="HTTP connections" />}
      {!resource.loading && !resource.error && (rows.length === 0
        ? <p className="text-sm text-muted-foreground">No HTTP connections yet.</p>
        : <Table>
          <TableHeader><TableRow>
            <TableHead>Group</TableHead><TableHead>Name</TableHead><TableHead>Note</TableHead><TableHead>Origin</TableHead><TableHead>Auth</TableHead><TableHead>Credentials</TableHead><TableHead className="text-right">Actions</TableHead>
          </TableRow></TableHeader>
          <TableBody>
            {active.length > 0 && archived.length > 0 && <TableRow><TableCell colSpan={7}><h3>Active HTTP connections</h3></TableCell></TableRow>}
            {active.map(renderRow)}
            {archived.length > 0 && <TableRow><TableCell colSpan={7}><h3>Archived HTTP connections</h3></TableCell></TableRow>}
            {archived.map(renderRow)}
          </TableBody>
        </Table>)}
      <Dialog open={formDialog !== null} onOpenChange={open => { if (!open && !pending) setFormDialog(null) }}>
        <DialogContent onCloseAutoFocus={restoreFocus}>
          <DialogHeader>
            <DialogTitle>{formDialog?.mode === "edit" ? `Edit ${formDialog.connection.name}` : "New HTTP connection"}</DialogTitle>
            <DialogDescription>Saved credentials, including Basic username, are never shown. Blank secret fields preserve values for the same authentication mode.</DialogDescription>
          </DialogHeader>
          {formDialog && <HTTPForm key={formDialog.mode === "edit" ? formDialog.connection.id : "new"} connection={formDialog.mode === "edit" ? formDialog.connection : null} groups={groups} pending={pending} error={formError} onSubmit={request => void submit(request)} onCancel={() => { if (!pending) setFormDialog(null) }} />}
        </DialogContent>
      </Dialog>
      <Dialog open={deleteTarget !== null} onOpenChange={open => { if (!open && !deletePending) setDeleteTarget(null) }}>
        <DialogContent onCloseAutoFocus={restoreFocus}>
          <DialogHeader>
            <DialogTitle>Delete HTTP connection</DialogTitle>
            <DialogDescription>This will permanently delete "{deleteTarget?.name}" and its note.</DialogDescription>
          </DialogHeader>
          {deleteError && <p role="alert" className="text-sm text-destructive">{deleteError}</p>}
          <DialogFooter>
            <Button type="button" variant="outline" disabled={deletePending} onClick={() => setDeleteTarget(null)}>Cancel</Button>
            <Button type="button" variant="destructive" disabled={deletePending} onClick={() => void confirmDelete()}>{deletePending ? "Deleting" : "Delete"}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
