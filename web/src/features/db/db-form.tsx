import { useState, type FormEvent } from "react"
import type { DBConnection, DBConnectionRequest, SSHConnection } from "@/api/types"
import { Button } from "@/components/ui/button"
import { DialogFooter } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"

/** Controlled DB form state. The password is always blank on open because
 * list/get responses are redacted; only a literal empty string serializes
 * as null so the stored value is retained on edit. The SSH connection is a
 * string select value: "0" means Direct, otherwise the profile ID. */
export interface DBFormState {
  name: string
  host: string
  port: string
  username: string
  password: string
  database: string
  sshConnectionID: string
}

export function emptyDBForm(): DBFormState {
  return {
    name: "",
    host: "",
    port: "0",
    username: "",
    password: "",
    database: "",
    sshConnectionID: "0",
  }
}

export function dbFormFromConnection(connection: DBConnection): DBFormState {
  return {
    name: connection.name,
    host: connection.host,
    port: String(connection.port),
    username: connection.username,
    password: "",
    database: connection.database,
    sshConnectionID: String(connection.ssh_connection_id),
  }
}

/** Blank passwords serialize as null (retain on edit, store nothing on
 * create); nonblank passwords are preserved verbatim, never trimmed. */
export function toDBRequest(form: DBFormState): DBConnectionRequest {
  return {
    name: form.name,
    host: form.host,
    port: Number(form.port),
    username: form.username,
    password: form.password === "" ? null : form.password,
    database: form.database,
    ssh_connection_id: Number(form.sshConnectionID),
  }
}

interface SSHOption {
  value: string
  label: string
}

/** Select options in order: Direct, the current missing value when nonzero
 * and absent from the profile list, then existing profiles in API order.
 * The form never requires a resolvable profile list: Direct is always
 * available and a saved nonzero ID always renders as a Missing option. */
function sshOptions(sshProfiles: readonly SSHConnection[], currentID: number): SSHOption[] {
  const options: SSHOption[] = [{ value: "0", label: "Direct" }]
  if (currentID !== 0 && !sshProfiles.some(profile => profile.id === currentID)) {
    options.push({ value: String(currentID), label: `Missing SSH #${currentID}` })
  }
  for (const profile of sshProfiles) {
    options.push({
      value: String(profile.id),
      label: `${profile.name} — ${profile.host}:${profile.port}`,
    })
  }
  return options
}

export interface DBFormProps {
  /** The connection being edited, or null for create. */
  connection: DBConnection | null
  /** Existing SSH profiles backing the SSH select options. */
  sshProfiles: readonly SSHConnection[]
  pending: boolean
  error: string | null
  onSubmit: (request: DBConnectionRequest) => void
  onCancel: () => void
}

export function DBForm({ connection, sshProfiles, pending, error, onSubmit, onCancel }: DBFormProps) {
  const [form, setForm] = useState<DBFormState>(() =>
    connection ? dbFormFromConnection(connection) : emptyDBForm(),
  )
  const set = <K extends keyof DBFormState>(key: K, value: DBFormState[K]) =>
    setForm(current => ({ ...current, [key]: value }))

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault()
    onSubmit(toDBRequest(form))
  }

  const options = sshOptions(sshProfiles, Number(form.sshConnectionID))

  return (
    <form onSubmit={handleSubmit} className="grid gap-3">
      <div className="grid gap-1.5">
        <Label htmlFor="db-name">Name</Label>
        <Input
          id="db-name"
          value={form.name}
          onChange={event => set("name", event.target.value)}
          required
        />
      </div>
      <div className="grid gap-1.5">
        <Label htmlFor="db-host">Host</Label>
        <Input
          id="db-host"
          value={form.host}
          onChange={event => set("host", event.target.value)}
          required
        />
      </div>
      <div className="grid gap-1.5">
        <Label htmlFor="db-port">Port</Label>
        <Input
          id="db-port"
          type="number"
          min={0}
          max={65535}
          value={form.port}
          onChange={event => set("port", event.target.value)}
        />
      </div>
      <div className="grid gap-1.5">
        <Label htmlFor="db-username">Username</Label>
        <Input
          id="db-username"
          value={form.username}
          onChange={event => set("username", event.target.value)}
          required
        />
      </div>
      <div className="grid gap-1.5">
        <Label htmlFor="db-password">Password</Label>
        <Input
          id="db-password"
          type="password"
          autoComplete="new-password"
          placeholder="Leave blank to keep the stored value"
          value={form.password}
          onChange={event => set("password", event.target.value)}
        />
      </div>
      <div className="grid gap-1.5">
        <Label htmlFor="db-database">Database</Label>
        <Input
          id="db-database"
          value={form.database}
          onChange={event => set("database", event.target.value)}
          required
        />
      </div>
      <div className="grid gap-1.5">
        <Label htmlFor="db-ssh">SSH connection</Label>
        <Select value={form.sshConnectionID} onValueChange={value => set("sshConnectionID", value)}>
          <SelectTrigger id="db-ssh" className="w-full">
            <SelectValue placeholder="Select SSH connection" />
          </SelectTrigger>
          <SelectContent>
            {options.map(option => (
              <SelectItem key={option.value} value={option.value}>
                {option.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
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
