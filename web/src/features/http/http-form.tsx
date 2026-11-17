import { useState, type FormEvent } from "react"
import type { Group, HTTPAuthType, HTTPConnection, HTTPConnectionRequest } from "@/api/types"
import { SSHProfileCombobox } from "@/components/ssh-profile-combobox"
import { Button } from "@/components/ui/button"
import { DialogFooter } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"

interface HTTPFormProps {
  connection: HTTPConnection | null
  groups: readonly Group[]
  pending: boolean
  error: string | null
  onSubmit: (request: HTTPConnectionRequest) => void
  onCancel: () => void
}

export function HTTPForm({ connection, groups, pending, error, onSubmit, onCancel }: HTTPFormProps) {
  const [name, setName] = useState(connection?.name ?? "")
  const [origin, setOrigin] = useState(connection?.origin ?? "")
  const [authType, setAuthType] = useState<HTTPAuthType>(connection?.auth_type ?? "bearer")
  const [note, setNote] = useState(connection?.note ?? "")
  const [groupID, setGroupID] = useState(String(connection?.group_id ?? 0))
  const [credential, setCredential] = useState("")
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")

  const changeAuthType = (next: HTTPAuthType) => {
    if (next === authType) return
    setAuthType(next)
    setCredential("")
    setUsername("")
    setPassword("")
  }
  const submit = (event: FormEvent) => {
    event.preventDefault()
    if (pending) return
    const request: HTTPConnectionRequest = { name, origin, auth_type: authType, note, group_id: Number(groupID) }
    // Blank entries are omitted, not empty-string clears. No saved secret is
    // fetched, including Basic username. Mode changes clear old values server-side.
    if (authType === "basic") {
      if (username !== "") request.username = username
      if (password !== "") request.password = password
    } else if (credential !== "") {
      request.credential = credential
    }
    onSubmit(request)
  }
  const groupOptions = [{ value: "0", label: "None" }]
  if (groupID !== "0" && !groups.some(group => String(group.id) === groupID)) {
    groupOptions.push({ value: groupID, label: `Missing group #${groupID}` })
  }
  groupOptions.push(...groups.map(group => ({ value: String(group.id), label: group.name })))
  const sameAuth = connection?.auth_type === authType
  const secretInput = (field: "Credential" | "Username" | "Password", value: string, setValue: (value: string) => void, saved: boolean) => (
    <div className="grid gap-1.5">
      <Label htmlFor={`http-${field.toLowerCase()}`}>{field}</Label>
      <Input id={`http-${field.toLowerCase()}`} type="password" autoComplete="new-password" value={value}
        onChange={event => setValue(event.target.value)} disabled={pending} maxLength={8192}
        placeholder={saved ? "Leave blank to keep the stored value" : "Not set"} />
      <p className="text-sm text-muted-foreground">{field} {saved ? "saved" : "missing"}</p>
    </div>
  )

  return (
    <form onSubmit={submit} autoComplete="off" className="grid gap-3">
      <div className="grid gap-1.5">
        <Label htmlFor="http-name">Name</Label>
        <Input id="http-name" value={name} onChange={event => setName(event.target.value)} required maxLength={100} pattern="[A-Za-z0-9._\-]+" disabled={pending} />
      </div>
      <div className="grid gap-1.5">
        <Label htmlFor="http-origin">Origin</Label>
        <Input id="http-origin" value={origin} onChange={event => setOrigin(event.target.value)} required maxLength={2048} placeholder="https://api.example.com:8443" disabled={pending} />
        <p className="text-sm text-muted-foreground">HTTP or HTTPS origin only: scheme://host[:port]. No path, query, fragment, credentials or trailing slash. Private hosts are allowed.</p>
        {origin.startsWith("http:") && <p className="text-sm text-destructive">HTTP is unencrypted: credentials and request/response data can be intercepted or changed. Prefer HTTPS.</p>}
      </div>
      <div className="grid gap-1.5">
        <Label htmlFor="http-group">Group</Label>
        <SSHProfileCombobox id="http-group" value={groupID} options={groupOptions} placeholder="None" searchPlaceholder="Search groups" emptyLabel="No groups found." onValueChange={setGroupID} disabled={pending} />
      </div>
      <fieldset disabled={pending} className="grid gap-2">
        <legend className="text-sm font-medium">Authentication</legend>
        <div className="flex flex-wrap gap-4">
          {([["bearer", "Bearer"], ["x_api_key", "X-API-Key"], ["basic", "Basic"]] as const).map(([value, label]) => (
            <label key={value} className="flex items-center gap-2 text-sm">
              <input type="radio" name="http-auth" value={value} checked={authType === value} onChange={() => changeAuthType(value)} />{label}
            </label>
          ))}
        </div>
      </fieldset>
      {authType === "basic" ? <>
        {secretInput("Username", username, setUsername, !!(sameAuth && connection?.has_username))}
        {secretInput("Password", password, setPassword, !!(sameAuth && connection?.has_password))}
      </> : secretInput("Credential", credential, setCredential, !!(sameAuth && connection?.has_credential))}
      <p className="text-sm text-muted-foreground">Leave secret fields blank to keep saved values for the same authentication mode. Changing modes removes the previous mode’s credentials. Incomplete profiles can be saved but cannot execute requests.</p>
      <div className="grid gap-1.5">
        <Label htmlFor="http-note">Note</Label>
        <Textarea id="http-note" value={note} onChange={event => setNote(event.target.value)} maxLength={4096} rows={3} disabled={pending} />
      </div>
      {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onCancel} disabled={pending}>Cancel</Button>
        <Button type="submit" disabled={pending}>{pending ? "Saving" : "Save"}</Button>
      </DialogFooter>
    </form>
  )
}
