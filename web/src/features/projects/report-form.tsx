import { useState, type FormEvent } from "react"
import type { Project, ReportRequest } from "@/api/types"
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
import { Textarea } from "@/components/ui/textarea"

/** Controlled report form state. The project is a required select backed
 * only by existing projects; it preselects the active project when one is
 * selected, but the user may choose any other existing project. */
export interface ReportFormState {
  project: string
  title: string
  summary: string
  agentModel: string
}

export function emptyReportForm(selectedProject: Project | null): ReportFormState {
  return {
    project: selectedProject?.name ?? "",
    title: "",
    summary: "",
    agentModel: "",
  }
}

export function toReportRequest(form: ReportFormState): ReportRequest {
  return {
    project: form.project,
    title: form.title,
    summary: form.summary,
    agent_model: form.agentModel,
  }
}

export interface ReportFormProps {
  /** Existing projects backing the required project select. */
  projects: readonly Project[]
  /** Active project preselected when the dialog opens. */
  selectedProject: Project | null
  pending: boolean
  error: string | null
  onSubmit: (request: ReportRequest) => void
  onCancel: () => void
}

/** Add Report dialog form. Submission is blocked until a project is chosen. */
export function ReportForm({
  projects,
  selectedProject,
  pending,
  error,
  onSubmit,
  onCancel,
}: ReportFormProps) {
  const [form, setForm] = useState<ReportFormState>(() => emptyReportForm(selectedProject))
  const set = <K extends keyof ReportFormState>(key: K, value: ReportFormState[K]) =>
    setForm(current => ({ ...current, [key]: value }))

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault()
    if (form.project === "") return
    onSubmit(toReportRequest(form))
  }

  return (
    <form onSubmit={handleSubmit} className="grid gap-3">
      <div className="grid gap-1.5">
        <Label htmlFor="report-project">Project</Label>
        <Select value={form.project} onValueChange={value => set("project", value)}>
          <SelectTrigger id="report-project" className="w-full">
            <SelectValue placeholder="Select a project" />
          </SelectTrigger>
          <SelectContent>
            {projects.map(project => (
              <SelectItem key={project.id} value={project.name}>
                {project.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div className="grid gap-1.5">
        <Label htmlFor="report-title">Title</Label>
        <Input
          id="report-title"
          value={form.title}
          onChange={event => set("title", event.target.value)}
          required
        />
      </div>
      <div className="grid gap-1.5">
        <Label htmlFor="report-summary">Summary</Label>
        <Textarea
          id="report-summary"
          value={form.summary}
          onChange={event => set("summary", event.target.value)}
          required
        />
      </div>
      <div className="grid gap-1.5">
        <Label htmlFor="report-agent-model">Agent model</Label>
        <Input
          id="report-agent-model"
          value={form.agentModel}
          onChange={event => set("agentModel", event.target.value)}
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
          {pending ? "Saving" : "Create report"}
        </Button>
      </DialogFooter>
    </form>
  )
}
