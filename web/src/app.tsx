import { useCallback, useRef, useState } from "react"
import { api } from "@/api/client"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { useListResource } from "@/hooks/use-list-resource"
import { SSHTab } from "@/features/ssh/ssh-tab"
import { DBTab } from "@/features/db/db-tab"
import { ProjectsReportsTab } from "@/features/projects/projects-reports-tab"

export interface NotificationItem {
  id: number
  message: string
  kind: "success" | "error"
}

export type Notify = (message: string, kind: "success" | "error") => void

/** Global notification region: success uses a polite live region, errors use alert role. */
export function Notifications({ items }: { items: readonly NotificationItem[] }) {
  return (
    <div className="flex flex-col gap-2 px-6 py-2">
      {items.map((item) =>
        item.kind === "error" ? (
          <Alert key={item.id} variant="destructive">
            <AlertTitle>Error</AlertTitle>
            <AlertDescription>{item.message}</AlertDescription>
          </Alert>
        ) : (
          <Alert key={item.id} role="status" aria-live="polite">
            <AlertTitle>Success</AlertTitle>
            <AlertDescription>{item.message}</AlertDescription>
          </Alert>
        ),
      )}
    </div>
  )
}

export function App() {
  const ssh = useListResource(api.listSSH)
  const db = useListResource(api.listDB)
  const projects = useListResource(api.listProjects)

  const [notifications, setNotifications] = useState<NotificationItem[]>([])
  const nextNotificationID = useRef(1)
  const notify: Notify = useCallback((message, kind) => {
    setNotifications((current) => [
      ...current,
      { id: nextNotificationID.current++, message, kind },
    ])
  }, [])

  return (
    <div className="min-h-screen bg-background text-foreground">
      <header className="border-b px-6 py-4">
        <h1 className="text-xl font-semibold">Warden Hub</h1>
        <p className="text-sm text-muted-foreground">
          tailnet management plane — read-only view of secrets, execution happens on clients
        </p>
      </header>
      <Notifications items={notifications} />
      <Tabs defaultValue="ssh">
        <TabsList className="mx-4 mt-4">
          <TabsTrigger value="ssh">SSH</TabsTrigger>
          <TabsTrigger value="db">Databases</TabsTrigger>
          <TabsTrigger value="projects">Projects &amp; Reports</TabsTrigger>
        </TabsList>
        <TabsContent value="ssh">
          <SSHTab resource={ssh} notify={notify} />
        </TabsContent>
        <TabsContent value="db">
          <DBTab resource={db} sshProfiles={ssh.data} notify={notify} />
        </TabsContent>
        <TabsContent value="projects">
          <ProjectsReportsTab resource={projects} notify={notify} />
        </TabsContent>
      </Tabs>
    </div>
  )
}
