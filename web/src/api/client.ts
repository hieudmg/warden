import type {
  DBConnection,
  DBConnectionRequest,
  DependentsResponse,
  Project,
  ProjectRequest,
  Report,
  ReportRequest,
  SSHConnection,
  SSHConnectionRequest,
} from "./types"

/** Stable error envelope returned by the Warden JSON API. */
export class ApiError extends Error {
  readonly code: string
  readonly status: number

  constructor(code: string, message: string, status: number) {
    super(message)
    this.name = "ApiError"
    this.code = code
    this.status = status
  }
}

interface RequestOptions {
  method?: "GET" | "POST" | "PUT" | "DELETE"
  json?: unknown
  signal?: AbortSignal
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T | undefined> {
  const headers = new Headers()
  let body: string | undefined
  if (options.json !== undefined) {
    headers.set("Content-Type", "application/json")
    body = JSON.stringify(options.json)
  }

  let response: Response
  try {
    response = await fetch(path, {
      method: options.method ?? "GET",
      headers,
      body,
      signal: options.signal,
    })
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw error
    }
    throw new ApiError("network_error", error instanceof Error ? error.message : String(error), 0)
  }

  if (response.status === 204) {
    return undefined
  }

  const contentType = response.headers.get("Content-Type") ?? ""
  const text = await response.text()

  if (!response.ok) {
    if (contentType.includes("application/json") && text !== "") {
      try {
        const envelope = JSON.parse(text) as { code?: string; message?: string }
        throw new ApiError(
          envelope.code ?? `http_${response.status}`,
          envelope.message ?? response.statusText,
          response.status,
        )
      } catch (error) {
        if (error instanceof ApiError) throw error
      }
    }
    throw new ApiError(`http_${response.status}`, response.statusText || `HTTP ${response.status}`, response.status)
  }

  if (text === "") {
    return undefined
  }
  if (contentType.includes("application/json")) {
    return JSON.parse(text) as T
  }
  throw new ApiError(
    `http_${response.status}`,
    `unexpected content type ${contentType}`,
    response.status,
  )
}

export const api = {
  // SSH connections
  listSSH: (signal?: AbortSignal): Promise<SSHConnection[]> =>
    request<SSHConnection[]>("/api/v1/ssh-connections", { signal }) as Promise<SSHConnection[]>,
  createSSH: (payload: SSHConnectionRequest): Promise<SSHConnection> =>
    request<SSHConnection>("/api/v1/ssh-connections", { method: "POST", json: payload }) as Promise<SSHConnection>,
  updateSSH: (id: number, payload: SSHConnectionRequest): Promise<SSHConnection> =>
    request<SSHConnection>(`/api/v1/ssh-connections/${id}`, { method: "PUT", json: payload }) as Promise<SSHConnection>,
  deleteSSH: (id: number): Promise<void> =>
    request<void>(`/api/v1/ssh-connections/${id}`, { method: "DELETE" }).then(() => undefined),
  sshDependents: (id: number): Promise<DependentsResponse> =>
    request<DependentsResponse>(`/api/v1/ssh-connections/${id}/dependents`) as Promise<DependentsResponse>,

  // DB connections
  listDB: (signal?: AbortSignal): Promise<DBConnection[]> =>
    request<DBConnection[]>("/api/v1/db-connections", { signal }) as Promise<DBConnection[]>,
  createDB: (payload: DBConnectionRequest): Promise<DBConnection> =>
    request<DBConnection>("/api/v1/db-connections", { method: "POST", json: payload }) as Promise<DBConnection>,
  updateDB: (id: number, payload: DBConnectionRequest): Promise<DBConnection> =>
    request<DBConnection>(`/api/v1/db-connections/${id}`, { method: "PUT", json: payload }) as Promise<DBConnection>,
  deleteDB: (id: number): Promise<void> =>
    request<void>(`/api/v1/db-connections/${id}`, { method: "DELETE" }).then(() => undefined),
  dbDependents: (id: number): Promise<DependentsResponse> =>
    request<DependentsResponse>(`/api/v1/db-connections/${id}/dependents`) as Promise<DependentsResponse>,

  // Projects and reports
  listProjects: (signal?: AbortSignal): Promise<Project[]> =>
    request<Project[]>("/api/v1/projects", { signal }) as Promise<Project[]>,
  createProject: (payload: ProjectRequest): Promise<Project> =>
    request<Project>("/api/v1/projects", { method: "POST", json: payload }) as Promise<Project>,
  listReports: (project: string, signal?: AbortSignal): Promise<Report[]> =>
    request<Report[]>(
      `/api/v1/projects/${encodeURIComponent(project)}/reports`,
      { signal },
    ) as Promise<Report[]>,
  createReport: (payload: ReportRequest): Promise<Report> =>
    request<Report>("/api/v1/reports", { method: "POST", json: payload }) as Promise<Report>,
}
