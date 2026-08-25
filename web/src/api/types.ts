// API types matching the Go model JSON exactly (internal/model/api.go,
// internal/model/report.go). Secret values are never present in response
// types; Has* booleans report presence only.

export interface SSHConnection {
  id: number
  name: string
  host: string
  port: number
  username: string
  has_password: boolean
  has_private_key: boolean
  has_private_key_passphrase: boolean
  proxy_host: string
  proxy_port: number
  proxy_username: string
  has_proxy_password: boolean
  jump_connection_ids: string
  default_dir: string
  group_id: number
  group_name?: string
  created_at: string
  updated_at: string
}

export interface DBConnection {
  id: number
  name: string
  host: string
  port: number
  username: string
  has_password: boolean
  database: string
  ssh_connection_id: number
  group_id: number
  group_name?: string
  created_at: string
  updated_at: string
}

export interface Project {
  id: number
  name: string
}

export interface Group {
  id: number
  name: string
  ssh_connection_count: number
  db_connection_count: number
  created_at: string
  updated_at: string
}

export interface GroupRequest {
  name: string
}

export interface Report {
  id: number
  project: string
  title: string
  summary: string
  agent_model: string
  created_at: string
}

export interface DependentRef {
  id: number
  name: string
}

export interface DependentsResponse {
  ssh: DependentRef[]
  db: DependentRef[]
}

// Write payloads. Secret fields are string | null: null means "not
// provided" (keep the stored value on update); a blank input must never
// serialize as "" because that would clear the stored secret.
export interface SSHConnectionRequest {
  name: string
  host: string
  port: number
  username: string
  password: string | null
  private_key: string | null
  private_key_passphrase: string | null
  proxy_host: string
  proxy_port: number
  proxy_username: string
  proxy_password: string | null
  jump_connection_ids: string
  default_dir: string
  group_id: number
}

export interface DBConnectionRequest {
  name: string
  host: string
  port: number
  username: string
  password: string | null
  database: string
  ssh_connection_id: number
  group_id: number
}

export interface ProjectRequest {
  name: string
}

export interface ReportRequest {
  project: string
  title: string
  summary: string
  agent_model: string
}
