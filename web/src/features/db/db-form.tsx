import { useRef, useState, type FormEvent } from "react"
import type { DBConnection, DBConnectionRequest, DatabaseInfo, Group, SSHConnection } from "@/api/types"
import { Button } from "@/components/ui/button"
import { DialogFooter } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { SSHProfileCombobox, type SSHProfileOption } from "@/components/ssh-profile-combobox"
import { jumpOptionLabel } from "../ssh/jump-route"

/** Controlled DB form state. The password is always blank on open because
 * list/get responses are redacted; only a literal empty string serializes
 * as null so the stored value is retained on edit. The SSH connection is a
 * string select value: "0" means Direct, otherwise the profile ID. */
export interface DatabaseFormEntry {
  name: string
  isDefault: boolean
}

export interface DBFormState {
  name: string
  host: string
  port: string
  username: string
  password: string
  databases: DatabaseFormEntry[]
  sshConnectionID: string
  groupID: string
}

export function emptyDBForm(): DBFormState {
  return {
    name: "",
    host: "",
    port: "3306",
    username: "",
    password: "",
    databases: [{ name: "", isDefault: true }],
    sshConnectionID: "0",
    groupID: "0",
  }
}

function formDatabases(connection: DBConnection): DatabaseFormEntry[] {
  if (connection.databases && connection.databases.length > 0) {
    return connection.databases.map(database => ({
      name: database.name,
      isDefault: database.is_default,
    }))
  }
  return [{ name: connection.database, isDefault: true }]
}

export function dbFormFromConnection(connection: DBConnection): DBFormState {
  return {
    name: connection.name,
    host: connection.host,
    port: String(connection.port),
    username: connection.username,
    password: "",
    databases: formDatabases(connection),
    sshConnectionID: String(connection.ssh_connection_id),
    groupID: String(connection.group_id),
  }
}

/** Return a user-facing validation error for the database list, or null when
 * it has one valid default and only non-empty unique names. */
export function validateDatabases(databases: readonly DatabaseFormEntry[]): string | null {
  if (databases.length === 0) return "At least one database is required."
  if (databases.filter(database => database.isDefault).length !== 1) {
    return "Select exactly one default database."
  }

  const names = new Set<string>()
  for (const database of databases) {
    const name = database.name.trim()
    if (name === "") return "Database names cannot be blank."
    if (/[\/\u0000-\u001f\u007f]/.test(name)) {
      return "Database names cannot contain slashes or control characters."
    }
    if (names.has(name)) return "Database names must be unique."
    names.add(name)
  }
  return null
}

/** Blank passwords serialize as null (retain on edit, store nothing on
 * create); nonblank passwords are preserved verbatim, never trimmed. */
export function toDBRequest(form: DBFormState): DBConnectionRequest {
  const databases: DatabaseInfo[] = form.databases.map(database => ({
    name: database.name,
    is_default: database.isDefault,
  }))
  const defaultEntry = form.databases.find(database => database.isDefault)
  return {
    name: form.name,
    host: form.host,
    port: Number(form.port),
    username: form.username,
    password: form.password === "" ? null : form.password,
    database: defaultEntry?.name ?? "",
    databases,
    ssh_connection_id: Number(form.sshConnectionID),
    group_id: Number(form.groupID),
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
      label: jumpOptionLabel(profile),
    })
  }
  return options
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

export interface DBFormProps {
  /** The connection being edited, or null for create. */
  connection: DBConnection | null
  /** Existing SSH profiles backing the SSH select options. */
  sshProfiles: readonly SSHConnection[]
  /** Existing connection groups backing the group select options. */
  groups: readonly Group[]
  pending: boolean
  error: string | null
  onSubmit: (request: DBConnectionRequest) => void
  onCancel: () => void
}

export function DBForm({ connection, sshProfiles, groups, pending, error, onSubmit, onCancel }: DBFormProps) {
  const initialForm = connection ? dbFormFromConnection(connection) : emptyDBForm()
  const nextDatabaseID = useRef(0)
  const [form, setForm] = useState<DBFormState>(initialForm)
  const [databaseRowIDs, setDatabaseRowIDs] = useState(() =>
    initialForm.databases.map(() => nextDatabaseID.current++),
  )
  const [databaseError, setDatabaseError] = useState<string | null>(null)
  const set = <K extends keyof DBFormState>(key: K, value: DBFormState[K]) =>
    setForm(current => ({ ...current, [key]: value }))
  const updateDatabases = (update: (databases: DatabaseFormEntry[]) => DatabaseFormEntry[]) => {
    setForm(current => ({ ...current, databases: update(current.databases) }))
    setDatabaseError(null)
  }
  const setDatabaseName = (index: number, name: string) => {
    updateDatabases(databases => databases.map((database, databaseIndex) =>
      databaseIndex === index ? { ...database, name } : database,
    ))
  }
  const setDefaultDatabase = (index: number) => {
    updateDatabases(databases => databases.map((database, databaseIndex) => ({
      ...database,
      isDefault: databaseIndex === index,
    })))
  }
  const addDatabase = () => {
    updateDatabases(databases => [...databases, { name: "", isDefault: false }])
    setDatabaseRowIDs(ids => [...ids, nextDatabaseID.current++])
  }
  const removeDatabase = (index: number) => {
    if (form.databases.length <= 1) return
    updateDatabases(databases => {
      const remaining = databases.filter((_, databaseIndex) => databaseIndex !== index)
      if (!remaining.some(database => database.isDefault)) {
        remaining[0] = { ...remaining[0], isDefault: true }
      }
      return remaining
    })
    setDatabaseRowIDs(ids => ids.filter((_, databaseIndex) => databaseIndex !== index))
  }

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault()
    const validationError = validateDatabases(form.databases)
    if (validationError) {
      setDatabaseError(validationError)
      return
    }
    onSubmit(toDBRequest(form))
  }

  const options = sshOptions(sshProfiles, Number(form.sshConnectionID))
  const groupSelectOptions = groupOptions(groups, Number(form.groupID))

  return (
    <form onSubmit={handleSubmit} autoComplete="off" className="grid gap-3">
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
        <Label htmlFor="db-group">Group</Label>
        <SSHProfileCombobox
          id="db-group"
          value={form.groupID}
          options={groupSelectOptions}
          placeholder="None"
          searchPlaceholder="Search groups"
          emptyLabel="No groups found."
          onValueChange={value => set("groupID", value)}
        />
      </div>
      <div className="flex items-end gap-2">
        <div className="grid gap-1.5 flex-[3] min-w-0">
          <Label htmlFor="db-username">Username</Label>
          <Input
            id="db-username"
            value={form.username}
            onChange={event => set("username", event.target.value)}
            required
          />
        </div>
        <span className="text-sm text-muted-foreground pb-2">@</span>
        <div className="grid gap-1.5 flex-[5] min-w-0">
          <Label htmlFor="db-host">Host</Label>
          <Input
            id="db-host"
            value={form.host}
            onChange={event => set("host", event.target.value)}
            required
          />
        </div>
        <span className="text-sm text-muted-foreground pb-2">:</span>
        <div className="grid gap-1.5 w-24">
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
      </div>
      <div className="grid gap-1.5">
        <Label htmlFor="db-password">Password</Label>
        <Input
          id="db-password"
          placeholder="Leave blank to keep the stored value"
          value={form.password}
          onChange={event => set("password", event.target.value)}
        />
      </div>
      <div className="grid gap-2">
        <div className="flex items-center justify-between gap-2">
          <Label>Databases</Label>
          <Button type="button" variant="outline" size="sm" onClick={addDatabase} disabled={pending}>
            Add database
          </Button>
        </div>
        <div className="grid gap-2">
          {form.databases.map((database, index) => (
            <div key={databaseRowIDs[index] ?? index} className="flex items-end gap-2">
              <div className="grid min-w-0 flex-1 gap-1.5">
                <Label htmlFor={`db-database-${index}`}>Database {index + 1}</Label>
                <Input
                  id={`db-database-${index}`}
                  value={database.name}
                  onChange={event => setDatabaseName(index, event.target.value)}
                  aria-required="true"
                />
              </div>
              <label className="flex h-8 items-center gap-1.5 pb-1 text-sm">
                <input
                  type="radio"
                  name="db-default-database"
                  aria-label={`Default database ${index + 1}`}
                  checked={database.isDefault}
                  onChange={() => setDefaultDatabase(index)}
                />
                Default
              </label>
              <Button
                type="button"
                variant="outline"
                size="sm"
                aria-label={`Remove database ${index + 1}`}
                onClick={() => removeDatabase(index)}
                disabled={pending || form.databases.length === 1}
              >
                Remove
              </Button>
            </div>
          ))}
        </div>
      </div>
      <div className="grid gap-1.5">
        <Label htmlFor="db-ssh">SSH connection</Label>
        <SSHProfileCombobox
          id="db-ssh"
          value={form.sshConnectionID}
          options={options}
          placeholder="Select SSH connection"
          searchPlaceholder="Search SSH connections"
          emptyLabel="No SSH connections found."
          onValueChange={value => set("sshConnectionID", value)}
        />
      </div>
      {(databaseError || error) && (
        <p role="alert" className="text-sm text-destructive">
          {databaseError || error}
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
