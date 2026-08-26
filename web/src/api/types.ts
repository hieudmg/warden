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
  key_pair_id: number
  key_pair_name?: string
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

// Key pairs. Summary is the metadata-only view: presence flags, never raw
// key material. Vault is the single-pair GET view that discloses raw
// public/private/passphrase values. Request secret fields are string | null:
// null means "not provided" (keep the stored value on update); a non-null
// empty string explicitly clears.
export interface KeyPairSummary {
  id: number
  name: string
  has_public_key: boolean
  has_private_key: boolean
  has_private_key_passphrase: boolean
  created_at: string
  updated_at: string
}

export interface KeyPairVault extends KeyPairSummary {
  public_key: string
  private_key: string
  private_key_passphrase: string
}

export interface KeyPairRequest {
  name: string
  public_key: string | null
  private_key: string | null
  private_key_passphrase: string | null
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
// serialize as "" because that would clear the stored secret. KeyPairID
// selects a stored key pair; 0 means no stored pair selected. Password and
// key_pair_id are mutually exclusive: exactly one active auth source.
export interface SSHConnectionRequest {
  name: string
  host: string
  port: number
  username: string
  password: string | null
  key_pair_id: number
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
