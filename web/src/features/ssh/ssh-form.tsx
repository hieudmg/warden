import { useState, type FormEvent } from "react"
import type { Group, SSHConnection, SSHConnectionRequest } from "@/api/types"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { DialogFooter } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group"
import { Separator } from "@/components/ui/separator"
import { Textarea } from "@/components/ui/textarea"
import { SSHProfileCombobox, type SSHProfileOption } from "@/components/ssh-profile-combobox"
import { parseJumpRoute, serializeJumpRoute } from "./jump-route"
import { JumpRouteField } from "./jump-route-field"

/** Controlled SSH form state. Secrets are always blank on open because
 * list/get responses are redacted; only literal empty strings serialize
 * as null so stored values are retained on edit. Password and private
 * key are mutually exclusive auth modes selected by radio: switching
 * modes clears the inactive mode's secret client-side. */
export interface SSHFormState {
  name: string
  host: string
  port: string
  username: string
  authMode: "password" | "privateKey"
  password: string
  privateKey: string
  privateKeyPassphrase: string
  proxyHost: string
  proxyPort: string
  proxyUsername: string
  proxyPassword: string
  jumpIDs: number[]
  defaultDir: string
  groupID: string
}

export function emptySSHForm(): SSHFormState {
  return {
    name: "",
    host: "",
    port: "22",
    username: "",
    authMode: "password",
    password: "",
    privateKey: "",
    privateKeyPassphrase: "",
    proxyHost: "",
    proxyPort: "1080",
    proxyUsername: "",
    proxyPassword: "",
    jumpIDs: [],
    defaultDir: "",
    groupID: "0",
  }
}

export function sshFormFromConnection(connection: SSHConnection): SSHFormState {
  return {
    name: connection.name,
    host: connection.host,
    port: String(connection.port),
    username: connection.username,
    authMode:
      connection.has_private_key && !connection.has_password ? "privateKey" : "password",
    password: "",
    privateKey: "",
    privateKeyPassphrase: "",
    proxyHost: connection.proxy_host,
    proxyPort: String(connection.proxy_port),
    proxyUsername: connection.proxy_username,
    proxyPassword: "",
    jumpIDs: parseJumpRoute(connection.jump_connection_ids),
    defaultDir: connection.default_dir,
    groupID: String(connection.group_id),
  }
}

/** Blank secrets serialize as null (retain on edit, store nothing on
 * create); nonblank secrets are preserved verbatim, never trimmed. */
const nullableSecret = (value: string): string | null => (value === "" ? null : value)

export function toSSHRequest(form: SSHFormState): SSHConnectionRequest {
  const useKey = form.authMode === "privateKey"
  return {
    name: form.name,
    host: form.host,
    port: Number(form.port),
    username: form.username,
    password: useKey ? null : nullableSecret(form.password),
    private_key: useKey ? nullableSecret(form.privateKey) : null,
    private_key_passphrase: useKey ? nullableSecret(form.privateKeyPassphrase) : null,
    proxy_host: form.proxyHost,
    proxy_port: Number(form.proxyPort),
    proxy_username: form.proxyUsername,
    proxy_password: nullableSecret(form.proxyPassword),
    jump_connection_ids: serializeJumpRoute(form.jumpIDs),
    default_dir: form.defaultDir,
    group_id: Number(form.groupID),
  }
}

/** Select options in order: None (ungrouped), the current missing value
 * when nonzero and absent from the group list, then existing groups in API
 * order. A saved nonzero ID always renders as a Missing option so the form
 * never silently drops an assignment it cannot resolve. */
function groupOptions(groups: readonly Group[], currentID: number): SSHProfileOption[] {
  const options: SSHProfileOption[] = [{ value: "0", label: "None" }]
  if (currentID !== 0 && !groups.some(group => group.id === currentID)) {
    options.push({ value: String(currentID), label: `Missing group #${currentID}` })
  }
  for (const group of groups) {
    options.push({ value: String(group.id), label: group.name })
  }
  return options
}

export interface SSHFormProps {
  /** The connection being edited, or null for create. */
  connection: SSHConnection | null
  /** Existing SSH profiles backing the jump-route Add options and labels. */
  profiles: readonly SSHConnection[]
  /** Existing connection groups backing the group select options. */
  groups: readonly Group[]
  pending: boolean
  error: string | null
  onSubmit: (request: SSHConnectionRequest) => void
  onCancel: () => void
}

export function SSHForm({ connection, profiles, groups, pending, error, onSubmit, onCancel }: SSHFormProps) {
  const [form, setForm] = useState<SSHFormState>(() =>
    connection ? sshFormFromConnection(connection) : emptySSHForm(),
  )
  const [passthroughOpen, setPassthroughOpen] = useState(false)
  const set = <K extends keyof SSHFormState>(key: K, value: SSHFormState[K]) =>
    setForm(current => ({ ...current, [key]: value }))

  const groupSelectOptions = groupOptions(groups, Number(form.groupID))

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault()
    onSubmit(toSSHRequest(form))
  }

  return (
    <form onSubmit={handleSubmit} autoComplete="off" className="grid gap-3">
      <div className="grid gap-1.5">
        <Label htmlFor="ssh-name">Name</Label>
        <Input
          id="ssh-name"
          value={form.name}
          onChange={event => set("name", event.target.value)}
          required
        />
      </div>
      <div className="grid gap-1.5">
        <Label htmlFor="ssh-group">Group</Label>
        <SSHProfileCombobox
          id="ssh-group"
          value={form.groupID}
          options={groupSelectOptions}
          placeholder="None"
          searchPlaceholder="Search groups"
          emptyLabel="No groups found."
          onValueChange={value => set("groupID", value)}
        />
      </div>
      <div className="rounded-lg border">
        <Button
          type="button"
          variant="outline"
          className="w-full justify-start gap-2 border-0"
          aria-expanded={passthroughOpen}
          onClick={() => setPassthroughOpen(current => !current)}
        >
          <span>Server Passthrough</span>
          {form.proxyHost && <Badge variant="secondary">Proxy</Badge>}
          {form.jumpIDs.length > 0 && <Badge variant="secondary">Jump route</Badge>}
        </Button>
        {passthroughOpen && (
          <div className="grid gap-3 border-t p-3">
            <div className="flex items-end gap-2">
              <div className="grid gap-1.5 flex-[3] min-w-0">
                <Label htmlFor="ssh-proxy-username">Proxy username</Label>
                <Input
                  id="ssh-proxy-username"
                  value={form.proxyUsername}
                  onChange={event => set("proxyUsername", event.target.value)}
                />
              </div>
              <span className="text-sm text-muted-foreground pb-2">@</span>
              <div className="grid gap-1.5 flex-[5] min-w-0">
                <Label htmlFor="ssh-proxy-host">Proxy host</Label>
                <Input
                  id="ssh-proxy-host"
                  value={form.proxyHost}
                  onChange={event => set("proxyHost", event.target.value)}
                />
              </div>
              <span className="text-sm text-muted-foreground pb-2">:</span>
              <div className="grid gap-1.5 w-24">
                <Label htmlFor="ssh-proxy-port">Proxy port</Label>
                <Input
                  id="ssh-proxy-port"
                  type="number"
                  min={0}
                  max={65535}
                  value={form.proxyPort}
                  onChange={event => set("proxyPort", event.target.value)}
                />
              </div>
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="ssh-proxy-password">Proxy password</Label>
              <Input
                id="ssh-proxy-password"
                placeholder="Leave blank to keep the stored value"
                value={form.proxyPassword}
                onChange={event => set("proxyPassword", event.target.value)}
              />
            </div>
            <Separator decorative={false} />
            <div className="grid gap-1.5">
              <Label>Jump route</Label>
              <JumpRouteField
                value={form.jumpIDs}
                onChange={jumpIDs => set("jumpIDs", jumpIDs)}
                profiles={profiles}
                editingID={connection?.id}
              />
            </div>
          </div>
        )}
      </div>
      <div className="flex items-end gap-2">
        <div className="grid gap-1.5 flex-[3] min-w-0">
          <Label htmlFor="ssh-username">Username</Label>
          <Input
            id="ssh-username"
            value={form.username}
            onChange={event => set("username", event.target.value)}
            required
          />
        </div>
        <span className="text-sm text-muted-foreground pb-2">@</span>
        <div className="grid gap-1.5 flex-[5] min-w-0">
          <Label htmlFor="ssh-host">Host</Label>
          <Input
            id="ssh-host"
            value={form.host}
            onChange={event => set("host", event.target.value)}
            required
          />
        </div>
        <span className="text-sm text-muted-foreground pb-2">:</span>
        <div className="grid gap-1.5 w-24">
          <Label htmlFor="ssh-port">Port</Label>
          <Input
            id="ssh-port"
            type="number"
            min={1}
            max={65535}
            value={form.port}
            onChange={event => set("port", event.target.value)}
          />
        </div>
      </div>
      <Separator decorative={false} />
      <div className="grid gap-2">
        <Label>Authentication mode</Label>
        <RadioGroup
          value={form.authMode}
          onValueChange={value => {
            const authMode = value as "password" | "privateKey"
            setForm(current => ({
              ...current,
              authMode,
              password: authMode === "password" ? current.password : "",
              privateKey: authMode === "privateKey" ? current.privateKey : "",
              privateKeyPassphrase:
                authMode === "privateKey" ? current.privateKeyPassphrase : "",
            }))
          }}
        >
          <div className="flex items-center gap-2">
            <RadioGroupItem value="password" id="ssh-auth-password" />
            <Label htmlFor="ssh-auth-password">Password</Label>
          </div>
          <div className="flex items-center gap-2">
            <RadioGroupItem value="privateKey" id="ssh-auth-private-key" />
            <Label htmlFor="ssh-auth-private-key">Private key</Label>
          </div>
        </RadioGroup>
      </div>
      {form.authMode === "password" ? (
        <div className="grid gap-1.5">
          <Label htmlFor="ssh-password">Password</Label>
          <Input
            id="ssh-password"
            placeholder="Leave blank to keep the stored value"
            value={form.password}
            onChange={event => set("password", event.target.value)}
          />
        </div>
      ) : (
        <div className="grid gap-3">
          <div className="grid gap-1.5">
            <Label htmlFor="ssh-private-key">Private key</Label>
            <Textarea
              id="ssh-private-key"
              placeholder="Leave blank to keep the stored value"
              value={form.privateKey}
              onChange={event => set("privateKey", event.target.value)}
            />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="ssh-private-key-passphrase">Private key passphrase</Label>
            <Input
              id="ssh-private-key-passphrase"
              placeholder="Leave blank to keep the stored value"
              value={form.privateKeyPassphrase}
              onChange={event => set("privateKeyPassphrase", event.target.value)}
            />
          </div>
        </div>
      )}
      <Separator decorative={false} />
      <div className="grid gap-1.5">
        <Label htmlFor="ssh-default-dir">Default directory</Label>
        <Input
          id="ssh-default-dir"
          placeholder="/srv"
          value={form.defaultDir}
          onChange={event => set("defaultDir", event.target.value)}
        />
      </div>
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onCancel} disabled={pending}>
          Cancel
        </Button>
        <Button type="submit" disabled={pending}>
          {pending ? "Saving" : "Save"}
        </Button>
      </DialogFooter>
    </form>
  )
}
