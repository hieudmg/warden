import { useCallback, useRef, useState } from "react"
import { api } from "@/api/client"
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

export function App() {
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

  return (
    <div className="min-h-screen bg-background text-foreground">
      <header className="border-b px-6 py-4">
        <h1 className="text-xl font-semibold">Warden Hub</h1>
        <p className="text-sm text-muted-foreground">
          tailnet management plane — read-only view of secrets, execution happens on clients
        </p>
      </header>
      <Notifications items={notifications} onDismiss={dismissNotification} />
      <Tabs defaultValue="ssh">
        <TabsList className="mx-4 mt-4">
          <TabsTrigger value="ssh">SSH</TabsTrigger>
          <TabsTrigger value="db">Databases</TabsTrigger>
          <TabsTrigger value="groups">Groups</TabsTrigger>
          <TabsTrigger value="key-pairs">Key Pairs</TabsTrigger>
          <TabsTrigger value="projects">Projects &amp; Reports</TabsTrigger>
        </TabsList>
        <TabsContent value="ssh">
          <SSHTab resource={ssh} groups={groups.data} notify={notify} />
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
