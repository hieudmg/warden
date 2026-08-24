import { act, render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { beforeEach, describe, expect, test, vi } from "vitest"
import { api } from "@/api/client"
import type { Project, Report } from "@/api/types"
import type { ListResource } from "@/hooks/use-list-resource"
import { ProjectsReportsTab } from "./projects-reports-tab"

vi.mock("@/api/client", () => ({
  api: {
    listReports: vi.fn(),
    createReport: vi.fn(),
    createProject: vi.fn(),
  },
}))

const mockedAPI = vi.mocked(api)
const notify = vi.fn()

function project(id: number, name: string): Project {
  return { id, name }
}

function report(id: number, projectName: string, title: string): Report {
  return {
    id,
    project: projectName,
    title,
    summary: `line one for ${title}\nline two for ${title}`,
    agent_model: "gpt-4o",
    created_at: "2026-08-24T10:30:00Z",
  }
}

function projectsResource(projects: Project[]): ListResource<Project> {
  return {
    data: projects,
    loading: false,
    error: null,
    reload: vi.fn().mockResolvedValue(undefined),
  }
}

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>(res => {
    resolve = res
  })
  return { promise, resolve }
}

beforeEach(() => {
  notify.mockReset()
  mockedAPI.listReports.mockReset()
  mockedAPI.createReport.mockReset()
  mockedAPI.createProject.mockReset()
})

describe("ProjectsReportsTab", () => {
  test("renders Projects, Reports, and Report content panes in DOM order with the responsive grid", () => {
    render(
      <ProjectsReportsTab
        resource={projectsResource([project(1, "warden"), project(2, "storefront")])}
        notify={notify}
      />,
    )

    const headings = screen.getAllByRole("heading", { level: 2 })
    expect(headings.map(heading => heading.textContent)).toEqual([
      "Projects",
      "Reports",
      "Report content",
    ])

    const layout = screen.getByTestId("projects-layout")
    expect(layout).toHaveClass("grid-cols-1")
    expect(layout).toHaveClass("lg:grid-cols-[minmax(0,0.8fr)_minmax(0,1fr)_minmax(0,1.7fr)]")
  })

  test("selecting a project loads its reports and selecting a report shows its content", async () => {
    const wardenReport = report(10, "warden", "Warden v0.2")
    mockedAPI.listReports.mockResolvedValue([wardenReport])
    const user = userEvent.setup()

    render(
      <ProjectsReportsTab
        resource={projectsResource([project(1, "warden"), project(2, "storefront")])}
        notify={notify}
      />,
    )

    await user.click(screen.getByRole("button", { name: "warden" }))
    expect(mockedAPI.listReports).toHaveBeenCalledWith("warden", expect.any(AbortSignal))

    const reportButton = await screen.findByRole("button", { name: "Warden v0.2" })
    await user.click(reportButton)

    expect(screen.getByRole("heading", { name: "Warden v0.2" })).toBeInTheDocument()
    expect(screen.getByText("gpt-4o")).toBeInTheDocument()
    expect(screen.getByText("2026-08-24 10:30 UTC")).toBeInTheDocument()

    const summary = screen.getByText(/line one for Warden v0\.2/)
    expect(summary.textContent).toContain("line two for Warden v0.2")
    expect(summary).toHaveClass("whitespace-pre-wrap")
    expect(summary).toHaveClass("[overflow-wrap:anywhere]")
  })

  test("explains empty project, report, and selection states", async () => {
    const user = userEvent.setup()
    const { rerender } = render(
      <ProjectsReportsTab resource={projectsResource([])} notify={notify} />,
    )
    expect(screen.getByText("No projects yet.")).toBeInTheDocument()
    expect(screen.getByText("Select a project to see its reports.")).toBeInTheDocument()
    expect(screen.getByText("Select a report to view its content.")).toBeInTheDocument()

    mockedAPI.listReports.mockResolvedValue([])
    rerender(<ProjectsReportsTab resource={projectsResource([project(1, "warden")])} notify={notify} />)

    await user.click(screen.getByRole("button", { name: "warden" }))
    expect(await screen.findByText("No reports yet for this project.")).toBeInTheDocument()
    expect(screen.getByText("Select a report to view its content.")).toBeInTheDocument()
  })

  test("ignores a stale report response that resolves after a newer project selection", async () => {
    const wardenDeferred = deferred<Report[]>()
    const storefrontDeferred = deferred<Report[]>()
    mockedAPI.listReports
      .mockImplementationOnce(() => wardenDeferred.promise)
      .mockImplementationOnce(() => storefrontDeferred.promise)
    const user = userEvent.setup()

    render(
      <ProjectsReportsTab
        resource={projectsResource([project(1, "warden"), project(2, "storefront")])}
        notify={notify}
      />,
    )

    await user.click(screen.getByRole("button", { name: "warden" }))
    expect(mockedAPI.listReports).toHaveBeenCalledTimes(1)

    await user.click(screen.getByRole("button", { name: "storefront" }))
    expect(mockedAPI.listReports).toHaveBeenCalledTimes(2)

    // The newer request resolves first with storefront data.
    await act(async () => {
      storefrontDeferred.resolve([report(2, "storefront", "Storefront report")])
    })
    expect(await screen.findByText("Storefront report")).toBeInTheDocument()

    // The stale (older) warden response resolves afterwards; it must be dropped.
    await act(async () => {
      wardenDeferred.resolve([report(1, "warden", "Warden report")])
    })
    expect(screen.getByText("Storefront report")).toBeInTheDocument()
    expect(screen.queryByText("Warden report")).not.toBeInTheDocument()
  })

  test("creates a report on a selected project and switches the UI to it", async () => {
    const wardenReport = report(10, "warden", "Warden v0.2")
    const created = report(42, "storefront", "Storefront release")
    mockedAPI.listReports.mockImplementation((name: string) =>
      Promise.resolve(name === "warden" ? [wardenReport] : []),
    )
    mockedAPI.createReport.mockResolvedValue(created)
    const user = userEvent.setup()

    render(
      <ProjectsReportsTab
        resource={projectsResource([project(1, "warden"), project(2, "storefront")])}
        notify={notify}
      />,
    )

    await user.click(screen.getByRole("button", { name: "warden" }))
    expect(await screen.findByText("Warden v0.2")).toBeInTheDocument()

    await user.click(screen.getByRole("button", { name: "Add report" }))

    // The dialog preselects the active project via a select backed by existing projects.
    const projectSelect = screen.getByRole("combobox", { name: "Project" })
    expect(projectSelect).toHaveTextContent("warden")

    // The user may choose a different existing project before submission.
    await user.click(projectSelect)
    await user.click(await screen.findByRole("option", { name: "storefront" }))

    await user.type(screen.getByLabelText("Title"), "Storefront release")
    await user.type(screen.getByLabelText("Summary"), "shipped")
    await user.type(screen.getByLabelText("Agent model"), "gpt-4o")
    await user.click(screen.getByRole("button", { name: "Create report" }))

    // The UI switches to storefront and selects the returned report's content.
    expect(await screen.findByRole("heading", { name: "Storefront release" })).toBeInTheDocument()
    await waitFor(() => {
      expect(screen.getByRole("button", { name: "storefront" })).toHaveAttribute("aria-pressed", "true")
      expect(screen.getByRole("button", { name: "warden" })).toHaveAttribute("aria-pressed", "false")
    })
    expect(notify).toHaveBeenCalledWith("Report created.", "success")
  })

  test("creates a project, refreshes the project list, and notifies", async () => {
    const reload = vi.fn().mockResolvedValue(undefined)
    mockedAPI.createProject.mockResolvedValue({ id: 2, name: "storefront" })
    const user = userEvent.setup()

    render(
      <ProjectsReportsTab
        resource={{ data: [project(1, "warden")], loading: false, error: null, reload }}
        notify={notify}
      />,
    )

    await user.click(screen.getByRole("button", { name: "New project" }))
    await user.type(screen.getByLabelText("Name"), "storefront")
    await user.click(screen.getByRole("button", { name: "Create project" }))

    await waitFor(() => expect(reload).toHaveBeenCalledTimes(1))
    expect(notify).toHaveBeenCalledWith('Created project "storefront".', "success")
  })

  test("reports expose no edit or delete controls", async () => {
    mockedAPI.listReports.mockResolvedValue([report(10, "warden", "Warden v0.2")])
    const user = userEvent.setup()

    render(
      <ProjectsReportsTab resource={projectsResource([project(1, "warden")])} notify={notify} />,
    )

    await user.click(screen.getByRole("button", { name: "warden" }))
    const reportButton = await screen.findByRole("button", { name: "Warden v0.2" })
    await user.click(reportButton)

    expect(screen.queryByRole("button", { name: /edit/i })).not.toBeInTheDocument()
    expect(screen.queryByRole("button", { name: /delete/i })).not.toBeInTheDocument()
  })

  test("shows a report load error with role alert and a Retry action", async () => {
    const user = userEvent.setup()
    mockedAPI.listReports.mockRejectedValue(new Error("reports unavailable"))
    render(
      <ProjectsReportsTab resource={projectsResource([project(1, "warden")])} notify={notify} />,
    )

    await user.click(screen.getByRole("button", { name: "warden" }))
    const alert = await screen.findByRole("alert")
    expect(alert).toHaveTextContent("Unable to load reports for warden")
    expect(alert).toHaveTextContent("reports unavailable")
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument()
  })

  test("shows project creation errors with role alert", async () => {
    const user = userEvent.setup()
    mockedAPI.createProject.mockRejectedValue(new Error("project exists"))
    render(
      <ProjectsReportsTab resource={projectsResource([project(1, "warden")])} notify={notify} />,
    )

    await user.click(screen.getByRole("button", { name: "New project" }))
    await user.type(screen.getByLabelText("Name"), "storefront")
    await user.click(screen.getByRole("button", { name: "Create project" }))

    const alert = await screen.findByRole("alert")
    expect(alert).toHaveTextContent("project exists")
  })

  test("shows report creation errors with role alert", async () => {
    const user = userEvent.setup()
    mockedAPI.listReports.mockResolvedValue([])
    mockedAPI.createReport.mockRejectedValue(new Error("report failed"))
    render(
      <ProjectsReportsTab resource={projectsResource([project(1, "warden")])} notify={notify} />,
    )

    await user.click(screen.getByRole("button", { name: "warden" }))
    await user.click(screen.getByRole("button", { name: "Add report" }))
    await user.type(screen.getByLabelText("Title"), "t")
    await user.type(screen.getByLabelText("Summary"), "s")
    await user.type(screen.getByLabelText("Agent model"), "gpt-4o")
    await user.click(screen.getByRole("button", { name: "Create report" }))

    const alert = await screen.findByRole("alert")
    expect(alert).toHaveTextContent("report failed")
  })
})
