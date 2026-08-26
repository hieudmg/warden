import { useState, type FormEvent } from "react"
import type { Group, KeyPairSummary, SSHConnection, SSHConnectionRequest } from "@/api/types"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { DialogFooter } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group"
import { Separator } from "@/components/ui/separator"
import { SSHProfileCombobox, type SSHProfileOption } from "@/components/ssh-profile-combobox"
import { parseJumpRoute, serializeJumpRoute } from "./jump-route"
import { JumpRouteField } from "./jump-route-field"

/** Controlled SSH form state. Secrets are always blank on open because
 * list/get responses are redacted; only literal empty strings serialize
 * as null so stored values are retained on edit. Password and stored key
 * pair are mutually exclusive auth modes selected by radio: switching
 * modes clears the inactive mode's selection client-side. */
export interface SSHFormState {
  name: string
  host: string
  port: string
  username: string
  authMode: "password" | "keyPair"
  password: string
  keyPairID: string
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
    keyPairID: "0",
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
    authMode: connection.key_pair_id !== 0 ? "keyPair" : "password",
    password: "",
    keyPairID: String(connection.key_pair_id),
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
  return {
    name: form.name,
    host: form.host,
    port: Number(form.port),
    username: form.username,
    password: form.authMode === "password" ? nullableSecret(form.password) : null,
    key_pair_id: form.authMode === "keyPair" ? Number(form.keyPairID) : 0,
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

/** Select options for stored key pairs: only pairs with a private key are
 * selectable. A saved nonzero ID that is absent from that set (dangling
 * reference or public-only pair) is prepended as a Missing option so the
 * form never silently drops an assignment it cannot resolve. */
function keyPairOptions(keyPairs: readonly KeyPairSummary[], currentID: number): SSHProfileOption[] {
  const options: SSHProfileOption[] = []
  if (currentID !== 0 && !keyPairs.some(pair => pair.id === currentID && pair.has_private_key)) {
    options.push({ value: String(currentID), label: `Missing key pair #${currentID}` })
  }
  for (const pair of keyPairs) {
    if (pair.has_private_key) {
      options.push({ value: String(pair.id), label: pair.name })
    }
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
  /** Stored key-pair summaries backing the stored-key selector. */
  keyPairs: readonly KeyPairSummary[]
  pending: boolean
  error: string | null
  onSubmit: (request: SSHConnectionRequest) => void
  onCancel: () => void
}

export function SSHForm({ connection, profiles, groups, keyPairs, pending, error, onSubmit, onCancel }: SSHFormProps) {
  const [form, setForm] = useState<SSHFormState>(() =>
    connection ? sshFormFromConnection(connection) : emptySSHForm(),
  )
  const [passthroughOpen, setPassthroughOpen] = useState(false)
  const [validationError, setValidationError] = useState<string | null>(null)
  const set = <K extends keyof SSHFormState>(key: K, value: SSHFormState[K]) =>
    setForm(current => ({ ...current, [key]: value }))

  const groupSelectOptions = groupOptions(groups, Number(form.groupID))
  const keyPairSelectOptions = keyPairOptions(keyPairs, Number(form.keyPairID))

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault()
    if (form.authMode === "keyPair" && form.keyPairID === "0") {
      setValidationError("Select a stored key pair.")
      return
    }
    setValidationError(null)
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
            const authMode = value as "password" | "keyPair"
            setForm(current => ({
              ...current,
              authMode,
              password: authMode === "password" ? current.password : "",
              keyPairID: authMode === "keyPair" ? current.keyPairID : "0",
            }))
            setValidationError(null)
          }}
        >
          <div className="flex items-center gap-2">
            <RadioGroupItem value="password" id="ssh-auth-password" />
            <Label htmlFor="ssh-auth-password">Password</Label>
          </div>
          <div className="flex items-center gap-2">
            <RadioGroupItem value="keyPair" id="ssh-auth-key-pair" />
            <Label htmlFor="ssh-auth-key-pair">Stored key pair</Label>
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
        <div className="grid gap-1.5">
          <Label htmlFor="ssh-key-pair">Stored key pair</Label>
          <SSHProfileCombobox
            id="ssh-key-pair"
            value={form.keyPairID}
            options={keyPairSelectOptions}
            placeholder="Select a stored key pair"
            searchPlaceholder="Search key pairs"
            emptyLabel="No key pairs with private keys found."
            onValueChange={value => {
              set("keyPairID", value)
              setValidationError(null)
            }}
          />
        </div>
      )}
      {validationError && (
        <p role="alert" className="text-sm text-destructive">
          {validationError}
        </p>
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
