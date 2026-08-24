import { useState, type FormEvent } from "react"
import type { ProjectRequest } from "@/api/types"
import { Button } from "@/components/ui/button"
import { DialogFooter } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"

export interface ProjectFormProps {
  pending: boolean
  error: string | null
  onSubmit: (request: ProjectRequest) => void
  onCancel: () => void
}

/** Project creation dialog form. */
export function ProjectForm({ pending, error, onSubmit, onCancel }: ProjectFormProps) {
  const [name, setName] = useState("")

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault()
    onSubmit({ name })
  }

  return (
    <form onSubmit={handleSubmit} className="grid gap-3">
      <div className="grid gap-1.5">
        <Label htmlFor="project-name">Name</Label>
        <Input
          id="project-name"
          value={name}
          onChange={event => setName(event.target.value)}
          required
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
          {pending ? "Saving" : "Create project"}
        </Button>
      </DialogFooter>
    </form>
  )
}
