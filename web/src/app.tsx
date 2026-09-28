import { useCallback, useEffect, useRef, useState } from "react"
import { api } from "@/api/client"
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
import {
  Toast,
  ToastClose,
  ToastDescription,
  ToastProvider,
  ToastTitle,
  ToastViewport,
} from "@/components/ui/toast"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { useListResource } from "@/hooks/use-list-resource"
import { SSHTab } from "@/features/ssh/ssh-tab"
import { DBTab } from "@/features/db/db-tab"
import { GroupsTab } from "@/features/groups/groups-tab"
import { KeyPairsTab } from "@/features/key-pairs/key-pairs-tab"
import { ProjectsReportsTab } from "@/features/projects/projects-reports-tab"

export interface NotificationItem {
  id: number
  message: string
  kind: "success" | "error"
}

export type Notify = (message: string, kind: "success" | "error") => void

type Route = "ssh" | "db" | "groups" | "key-pairs" | "projects"

const routePaths: Record<Route, string> = {
  ssh: "/ssh",
  db: "/databases",
  groups: "/groups",
  "key-pairs": "/key-pairs",
  projects: "/projects",
}

function routeForPath(pathname: string): Route {
  return (Object.entries(routePaths).find(([, path]) => path === pathname)?.[0] as Route | undefined) ?? "ssh"
}

function normalizePath(route: Route): void {
  const path = routePaths[route]
  if (window.location.pathname !== path) window.history.replaceState({}, "", path)
}

/** Global notification region: success uses a polite live region, errors use alert role. */
export function Notifications({
  items,
  onDismiss,
}: {
  items: readonly NotificationItem[]
  onDismiss: (id: number) => void
}) {
  return (
    <ToastProvider>
      {items.map((item) => (
        <Toast
          key={item.id}
          variant={item.kind === "error" ? "destructive" : "default"}
          role={item.kind === "error" ? "alert" : "status"}
          aria-live={item.kind === "error" ? "assertive" : "polite"}
          onOpenChange={(open) => {
            if (!open) onDismiss(item.id)
          }}
        >
          <ToastTitle>{item.kind === "error" ? "Error" : "Success"}</ToastTitle>
          <ToastDescription>{item.message}</ToastDescription>
          <ToastClose />
        </Toast>
      ))}
      <ToastViewport />
    </ToastProvider>
  )
}

type TransferMode = "export" | "import"

const exportFilename = "warden-data.json"

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

/** Triggers a browser download for an in-memory blob. */
function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob)
  try {
    const link = document.createElement("a")
    link.href = url
    link.download = filename
    link.rel = "noopener"
    document.body.append(link)
    link.click()
    link.remove()
  } finally {
    URL.revokeObjectURL(url)
  }
}

interface DataTransferActionsProps {
  onImported: () => Promise<void>
  notify: Notify
}

/**
 * Export/import controls for migrating data to another server. Both flows
 * warn first: the export file is unencrypted and carries plaintext secrets.
 */
function DataTransferActions({ onImported, notify }: DataTransferActionsProps) {
  const [mode, setMode] = useState<TransferMode | null>(null)
  const [file, setFile] = useState<File | null>(null)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const open = (next: TransferMode) => {
    setMode(next)
    setFile(null)
    setError(null)
  }

  const close = () => {
    if (pending) return
    setMode(null)
    setFile(null)
    setError(null)
  }

  const confirmExport = async () => {
    setPending(true)
    setError(null)
    try {
      const blob = await api.exportData()
      downloadBlob(blob, exportFilename)
      notify(`Exported data to ${exportFilename}. Delete it after migration.`, "success")
      setMode(null)
    } catch (err) {
      setError(`Export failed: ${errorMessage(err)}`)
    } finally {
      setPending(false)
    }
  }

  const confirmImport = async () => {
    if (!file) return
    setPending(true)
    setError(null)
    try {
      await api.importData(file)
      await onImported()
      notify("Imported data successfully.", "success")
      setMode(null)
      setFile(null)
    } catch (err) {
      setError(`Import failed: ${errorMessage(err)}`)
    } finally {
      setPending(false)
    }
  }

  return (
    <>
      <div className="flex gap-2">
        <Button type="button" variant="outline" size="sm" onClick={() => open("export")}>
          Export data
        </Button>
        <Button type="button" variant="outline" size="sm" onClick={() => open("import")}>
          Import data
        </Button>
      </div>
      <Dialog
        open={mode !== null}
        onOpenChange={isOpen => {
          if (!isOpen) close()
        }}
      >
        <DialogContent>
          {mode === "export" ? (
            <>
              <DialogHeader>
                <DialogTitle>Export data</DialogTitle>
                <DialogDescription>
                  The export file is unencrypted JSON containing plaintext credentials such as
                  passwords and private keys. Store it securely and delete it after migration.
                </DialogDescription>
              </DialogHeader>
              {error && (
                <p role="alert" className="text-sm text-destructive">
                  {error}
                </p>
              )}
              <DialogFooter>
                <Button type="button" variant="outline" onClick={close} disabled={pending}>
                  Cancel
                </Button>
                <Button type="button" onClick={() => void confirmExport()} disabled={pending}>
                  {pending ? "Exporting" : "Export"}
                </Button>
              </DialogFooter>
            </>
          ) : (
            <>
              <DialogHeader>
                <DialogTitle>Import data</DialogTitle>
                <DialogDescription>
                  Select an unencrypted Warden export file containing plaintext credentials. Import
                  replaces nothing: it only succeeds when this server has no managed data, and a
                  failed import leaves existing records unchanged.
                </DialogDescription>
              </DialogHeader>
              <div className="grid gap-1.5">
                <Label htmlFor="data-import-file">Export file</Label>
                <Input
                  id="data-import-file"
                  type="file"
                  accept="application/json,.json"
                  onChange={event => setFile(event.target.files?.[0] ?? null)}
                />
              </div>
              {error && (
                <p role="alert" className="text-sm text-destructive">
                  {error}
                </p>
              )}
              <DialogFooter>
                <Button type="button" variant="outline" onClick={close} disabled={pending}>
                  Cancel
                </Button>
                <Button
                  type="button"
                  onClick={() => void confirmImport()}
                  disabled={pending || file === null}
                >
                  {pending ? "Importing" : "Import"}
                </Button>
              </DialogFooter>
            </>
          )}
        </DialogContent>
      </Dialog>
    </>
  )
}

export function App() {
  const [route, setRoute] = useState<Route>(() => {
    const initialRoute = routeForPath(window.location.pathname)
    normalizePath(initialRoute)
    return initialRoute
  })
  const ssh = useListResource(api.listSSH)
  const db = useListResource(api.listDB)
  const groups = useListResource(api.listGroups)
  const projects = useListResource(api.listProjects)
  const keyPairs = useListResource(api.listKeyPairs)

  const [notifications, setNotifications] = useState<NotificationItem[]>([])
  const nextNotificationID = useRef(1)
  const dismissNotification = useCallback((id: number) => {
    setNotifications((current) => current.filter((item) => item.id !== id))
  }, [])
  const notify: Notify = useCallback((message, kind) => {
    setNotifications((current) => [
      ...current,
      { id: nextNotificationID.current++, message, kind },
    ])
  }, [])

  useEffect(() => {
    const handlePopState = () => {
      const nextRoute = routeForPath(window.location.pathname)
      normalizePath(nextRoute)
      setRoute(nextRoute)
    }
    window.addEventListener("popstate", handlePopState)
    return () => window.removeEventListener("popstate", handlePopState)
  }, [])

  const selectRoute = (value: string) => {
    const nextRoute = value as Route
    const nextPath = routePaths[nextRoute]
    if (!nextPath) return
    if (window.location.pathname !== nextPath) window.history.pushState({}, "", nextPath)
    setRoute(nextRoute)
  }

  // After a successful import the whole dataset changed, so every list
  // resource must be re-read.
  const reloadAll = useCallback(async () => {
    await Promise.all([
      ssh.reload(),
      db.reload(),
      groups.reload(),
      projects.reload(),
      keyPairs.reload(),
    ])
  }, [ssh.reload, db.reload, groups.reload, projects.reload, keyPairs.reload])

  return (
    <div className="flex min-h-screen flex-col bg-background text-foreground">
      <header className="border-b px-6 py-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h1 className="text-xl font-semibold">Warden Hub</h1>
            <p className="text-sm text-muted-foreground">
              tailnet management plane — read-only view of secrets, execution happens on clients
            </p>
          </div>
          <DataTransferActions onImported={reloadAll} notify={notify} />
        </div>
      </header>
      <Notifications items={notifications} onDismiss={dismissNotification} />
      <Tabs value={route} onValueChange={selectRoute} className="min-h-0 flex-1">
        <TabsList className="mx-4 mt-4 shrink-0">
          <TabsTrigger value="ssh">SSH</TabsTrigger>
          <TabsTrigger value="db">Databases</TabsTrigger>
          <TabsTrigger value="groups">Groups</TabsTrigger>
          <TabsTrigger value="key-pairs">Key Pairs</TabsTrigger>
          <TabsTrigger value="projects">Projects &amp; Reports</TabsTrigger>
        </TabsList>
        <TabsContent value="ssh">
          <SSHTab resource={ssh} groups={groups.data} keyPairs={keyPairs.data} notify={notify} />
        </TabsContent>
        <TabsContent value="db">
          <DBTab resource={db} sshProfiles={ssh.data} groups={groups.data} notify={notify} />
        </TabsContent>
        <TabsContent value="groups">
          <GroupsTab resource={groups} notify={notify} />
        </TabsContent>
        <TabsContent value="key-pairs">
          <KeyPairsTab resource={keyPairs} notify={notify} />
        </TabsContent>
        <TabsContent value="projects">
          <ProjectsReportsTab resource={projects} notify={notify} />
        </TabsContent>
      </Tabs>
    </div>
  )
}
