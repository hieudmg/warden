import { useCallback, useEffect, useRef, useState } from "react"
import ReactMarkdown from "react-markdown"
import { api } from "@/api/client"
import type { Project, ProjectRequest, Report, ReportRequest } from "@/api/types"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { ResourceError } from "@/components/resource-error"
import type { ListResource } from "@/hooks/use-list-resource"
import { ProjectForm } from "./project-form"
import { ReportForm } from "./report-form"

export interface ProjectsReportsTabProps {
  resource: ListResource<Project>
  notify: (message: string, kind: "success" | "error") => void
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

/** Deterministic UTC timestamp label for a report's server-generated time. */
function formatTimestamp(iso: string): string {
  const date = new Date(iso)
  const pad = (n: number) => String(n).padStart(2, "0")
  return `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())} ${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())} UTC`
}

const WEEKDAYS = [
  "Sunday",
  "Monday",
  "Tuesday",
  "Wednesday",
  "Thursday",
  "Friday",
  "Saturday",
] as const

/** UTC calendar date key (YYYY-MM-DD) used to group reports by day. */
function utcDateKey(iso: string): string {
  const date = new Date(iso)
  const pad = (n: number) => String(n).padStart(2, "0")
  return `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())}`
}

/** Full weekday name and DD/MM/YYYY heading for a report's UTC date. */
function formatDateHeading(iso: string): string {
  const date = new Date(iso)
  const pad = (n: number) => String(n).padStart(2, "0")
  return `${pad(date.getUTCDate())}/${pad(date.getUTCMonth() + 1)}/${date.getUTCFullYear()} | ${WEEKDAYS[date.getUTCDay()]}`
}

/** First pane: projects with a New Project action. Names are stable unique
 * identifiers, so selection is matched by name. */
function ProjectList({
  projects,
  selected,
  onSelect,
}: {
  projects: readonly Project[]
  selected: Project | null
  onSelect: (project: Project) => void
}) {
  if (projects.length === 0) {
    return <p className="text-sm text-muted-foreground">No projects yet.</p>
  }
  return (
    <ul className="space-y-1">
      {projects.map(project => {
        const isSelected = selected?.name === project.name
        return (
          <li key={project.id}>
            <Button
              type="button"
              variant={isSelected ? "default" : "outline"}
              className="w-full justify-start"
              aria-pressed={isSelected}
              onClick={() => onSelect(project)}
            >
              {project.name}
            </Button>
          </li>
        )
      })}
    </ul>
  )
}

/** Second pane: immutable report list for the selected project, sorted by
 * created_at descending and grouped under full-weekday UTC date headings. */
function ReportList({
  reports,
  selected,
  onSelect,
}: {
  reports: readonly Report[]
  selected: Report | null
  onSelect: (report: Report) => void
}) {
  if (reports.length === 0) {
    return <p className="text-sm text-muted-foreground">No reports yet for this project.</p>
  }
  const sorted = [...reports].sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at))
  const groups: { date: string; reports: Report[] }[] = []
  for (const report of sorted) {
    const date = utcDateKey(report.created_at)
    const last = groups[groups.length - 1]
    if (last !== undefined && last.date === date) {
      last.reports.push(report)
    } else {
      groups.push({ date, reports: [report] })
    }
  }
  return (
    <div className="space-y-6">
      {groups.map(group => (
        <div key={group.date} className="space-y-1">
          <h3 className="text-sm font-semibold text-muted-foreground">
            {formatDateHeading(group.reports[0].created_at)}
          </h3>
          <ul className="space-y-1">
            {group.reports.map(report => {
              const isSelected = selected?.id === report.id
              return (
                <li key={report.id}>
                  <Button
                    type="button"
                    variant={isSelected ? "default" : "outline"}
                    className="w-full justify-start"
                    aria-pressed={isSelected}
                    onClick={() => onSelect(report)}
                  >
                    {report.title}
                  </Button>
                </li>
              )
            })}
          </ul>
        </div>
      ))}
    </div>
  )
}

/** Third pane: complete immutable report content with Markdown summary that
 * wraps within the pane. Raw HTML remains disabled for untrusted reports. */
function ReportContent({ report }: { report: Report | null }) {
  if (!report) {
    return <p className="text-sm text-muted-foreground">Select a report to view its content.</p>
  }
  return (
    <article className="space-y-2">
      <h3 className="text-base font-semibold">{report.title}</h3>
      <dl className="space-y-1 text-sm">
        <div className="flex gap-2">
          <dt className="shrink-0 text-muted-foreground">Agent model</dt>
          <dd>{report.agent_model}</dd>
        </div>
        <div className="flex gap-2">
          <dt className="shrink-0 text-muted-foreground">Created</dt>
          <dd>{formatTimestamp(report.created_at)}</dd>
        </div>
      </dl>
      <div
        className="space-y-0.5 leading-snug [overflow-wrap:anywhere] [&_h1]:text-lg [&_h1]:font-semibold [&_h1]:leading-tight [&_h2]:text-base [&_h2]:font-semibold [&_h2]:leading-tight [&_h3]:font-semibold [&_h3]:leading-tight [&_ol]:list-decimal [&_ol]:pl-5 [&_ul]:list-disc [&_ul]:pl-5 [&_p]:whitespace-pre-wrap [&_li]:whitespace-pre-wrap [&_pre]:whitespace-pre-wrap [&_pre]:[overflow-wrap:anywhere]"
      >
        <ReactMarkdown skipHtml>{report.summary}</ReactMarkdown>
      </div>
    </article>
  )
}

export function ProjectsReportsTab({ resource, notify }: ProjectsReportsTabProps) {
  const [selectedProject, setSelectedProject] = useState<Project | null>(null)
  const [reports, setReports] = useState<Report[]>([])
  const [reportsLoading, setReportsLoading] = useState(false)
  const [reportsError, setReportsError] = useState<Error | null>(null)
  const [selectedReport, setSelectedReport] = useState<Report | null>(null)

  const [projectDialog, setProjectDialog] = useState(false)
  const [projectPending, setProjectPending] = useState(false)
  const [projectError, setProjectError] = useState<string | null>(null)

  const [reportDialog, setReportDialog] = useState(false)
  const [reportPending, setReportPending] = useState(false)
  const [reportError, setReportError] = useState<string | null>(null)

  // Controlled dialogs have no DialogTrigger, so Radix cannot restore focus
  // to the opener on close; capture the trigger element and restore it via
  // the Dialog primitive's onCloseAutoFocus hook (spec: focus returns to the
  // trigger on close).
  const lastTriggerRef = useRef<HTMLElement | null>(null)

  // Abortable report loading per project, mirroring useListResource:
  // each request aborts the previous and stamps a monotonic id so stale
  // responses never overwrite the current project's reports.
  const requestID = useRef(0)
  const controller = useRef<AbortController | null>(null)

  const loadReports = useCallback(async (project: Project): Promise<Report[]> => {
    const id = ++requestID.current
    controller.current?.abort()
    const next = new AbortController()
    controller.current = next
    setReportsLoading(true)
    setReportsError(null)
    try {
      const data = await api.listReports(project.name, next.signal)
      if (id === requestID.current) {
        setReports(data)
        setReportsLoading(false)
        return data
      }
    } catch (error) {
      if (!next.signal.aborted && id === requestID.current) {
        setReportsLoading(false)
        setReportsError(error as Error)
      }
    }
    return []
  }, [])

  useEffect(() => () => controller.current?.abort(), [])

  const selectProject = (project: Project) => {
    setSelectedProject(project)
    setSelectedReport(null)
    void loadReports(project)
  }

  const handleCreateProject = async (request: ProjectRequest) => {
    setProjectPending(true)
    setProjectError(null)
    try {
      await api.createProject(request)
      await resource.reload()
      setProjectDialog(false)
      notify(`Created project "${request.name}".`, "success")
    } catch (error) {
      setProjectError(errorMessage(error))
    } finally {
      setProjectPending(false)
    }
  }

  const handleCreateReport = async (request: ReportRequest) => {
    setReportPending(true)
    setReportError(null)
    try {
      const created = await api.createReport(request)
      // The submitted project is one of the existing projects backing the
      // form's required select; fall back defensively if it ever disappears.
      const target =
        resource.data.find(candidate => candidate.name === created.project) ?? {
          id: -1,
          name: created.project,
        }
      setSelectedProject(target)
      setSelectedReport(null)
      const refreshed = await loadReports(target)
      setSelectedReport(refreshed.find(candidate => candidate.id === created.id) ?? created)
      setReportDialog(false)
      notify("Report created.", "success")
    } catch (error) {
      setReportError(errorMessage(error))
    } finally {
      setReportPending(false)
    }
  }

  return (
    <div className="p-4 lg:h-full lg:min-h-0">
      <div
        className="grid grid-cols-1 gap-4 lg:h-full lg:min-h-0 lg:grid-cols-[minmax(0,0.8fr)_minmax(0,1fr)_minmax(0,1.7fr)]"
        data-testid="projects-layout"
      >
        <section className="min-w-0 lg:min-h-0 lg:overflow-y-auto" aria-labelledby="projects-heading">
          <div className="mb-3 flex items-center justify-between">
            <h2 id="projects-heading" className="text-lg font-semibold">
              Projects
            </h2>
            <Button
              type="button"
              onClick={event => {
                lastTriggerRef.current = event.currentTarget
                setProjectError(null)
                setProjectDialog(true)
              }}
            >
              New project
            </Button>
          </div>
          {resource.loading && <p className="text-sm text-muted-foreground">Loading…</p>}
          {resource.error && (
            <ResourceError
              error={resource.error}
              onRetry={() => void resource.reload()}
              label="projects"
            />
          )}
          {!resource.loading && !resource.error && (
            <ProjectList projects={resource.data} selected={selectedProject} onSelect={selectProject} />
          )}
        </section>

        <section className="min-w-0 lg:min-h-0 lg:overflow-y-auto" aria-labelledby="reports-heading">
          <div className="mb-3 flex items-center justify-between">
            <h2 id="reports-heading" className="text-lg font-semibold">
              Reports
            </h2>
            <Button
              type="button"
              onClick={event => {
                lastTriggerRef.current = event.currentTarget
                setReportError(null)
                setReportDialog(true)
              }}
            >
              Add report
            </Button>
          </div>
          {selectedProject === null ? (
            <p className="text-sm text-muted-foreground">Select a project to see its reports.</p>
          ) : reportsLoading ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : reportsError ? (
            <ResourceError
              error={reportsError}
              onRetry={() => void loadReports(selectedProject)}
              label={`reports for ${selectedProject.name}`}
            />
          ) : (
            <ReportList reports={reports} selected={selectedReport} onSelect={setSelectedReport} />
          )}
        </section>

        <section className="min-w-0 lg:min-h-0 lg:overflow-y-auto" aria-labelledby="report-content-heading">
          <h2 id="report-content-heading" className="mb-3 text-lg font-semibold">
            Report content
          </h2>
          <ReportContent report={selectedReport} />
        </section>
      </div>

      <Dialog
        open={projectDialog}
        onOpenChange={open => {
          if (!open && !projectPending) setProjectDialog(false)
        }}
      >
        <DialogContent
          onCloseAutoFocus={event => {
            event.preventDefault()
            lastTriggerRef.current?.focus()
          }}
        >
          <DialogHeader>
            <DialogTitle>Create project</DialogTitle>
            <DialogDescription>Projects group immutable reports.</DialogDescription>
          </DialogHeader>
          <ProjectForm
            pending={projectPending}
            error={projectError}
            onSubmit={request => void handleCreateProject(request)}
            onCancel={() => setProjectDialog(false)}
          />
        </DialogContent>
      </Dialog>

      <Dialog
        open={reportDialog}
        onOpenChange={open => {
          if (!open && !reportPending) setReportDialog(false)
        }}
      >
        <DialogContent
          onCloseAutoFocus={event => {
            event.preventDefault()
            lastTriggerRef.current?.focus()
          }}
        >
          <DialogHeader>
            <DialogTitle>Create report</DialogTitle>
            <DialogDescription>Reports are immutable once created.</DialogDescription>
          </DialogHeader>
          <ReportForm
            key={selectedProject?.name ?? "none"}
            projects={resource.data}
            selectedProject={selectedProject}
            pending={reportPending}
            error={reportError}
            onSubmit={request => void handleCreateReport(request)}
            onCancel={() => setReportDialog(false)}
          />
        </DialogContent>
      </Dialog>
    </div>
  )
}
