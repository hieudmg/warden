package model

import "time"

// SSHConnection is the redacted API representation of an SSH profile.
// Secret values are never serialized; Has* booleans report presence so the
// UI/CLI can show "password set" without exposing the value.
type SSHConnection struct {
	ID                      int64     `json:"id"`
	Name                    string    `json:"name"`
	Host                    string    `json:"host"`
	Port                    int       `json:"port"`
	Username                string    `json:"username"`
	HasPassword             bool      `json:"has_password"`
	HasPrivateKey           bool      `json:"has_private_key"`
	HasPrivateKeyPassphrase bool      `json:"has_private_key_passphrase"`
	ProxyHost               string    `json:"proxy_host,omitempty"`
	ProxyPort               int       `json:"proxy_port,omitempty"`
	ProxyUsername           string    `json:"proxy_username,omitempty"`
	HasProxyPassword        bool      `json:"has_proxy_password"`
	JumpConnectionIDs       string    `json:"jump_connection_ids"`
	CreatedAt               time.Time `json:"created_at"`
	UpdatedAt               time.Time `json:"updated_at"`
}

// DBConnection is the redacted API representation of a DB profile.
type DBConnection struct {
	ID              int64     `json:"id"`
	Name            string    `json:"name"`
	Host            string    `json:"host"`
	Port            int       `json:"port"`
	Username        string    `json:"username"`
	HasPassword     bool      `json:"has_password"`
	Database        string    `json:"database"`
	SSHConnectionID int64     `json:"ssh_connection_id"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// SSHConnectionRequest is the write payload for creating/updating an SSH
// profile. Secret fields are pointers: nil means "not provided" (keep the
// stored value on update, store nothing on create); non-nil replaces.
type SSHConnectionRequest struct {
	Name                 string  `json:"name"`
	Host                 string  `json:"host"`
	Port                 int     `json:"port"`
	Username             string  `json:"username"`
	Password             *string `json:"password"`
	PrivateKey           *string `json:"private_key"`
	PrivateKeyPassphrase *string `json:"private_key_passphrase"`
	ProxyHost            string  `json:"proxy_host"`
	ProxyPort            int     `json:"proxy_port"`
	ProxyUsername        string  `json:"proxy_username"`
	ProxyPassword        *string `json:"proxy_password"`
	JumpConnectionIDs    string  `json:"jump_connection_ids"`
}

// DBConnectionRequest is the write payload for a DB profile.
type DBConnectionRequest struct {
	Name            string  `json:"name"`
	Host            string  `json:"host"`
	Port            int     `json:"port"`
	Username        string  `json:"username"`
	Password        *string `json:"password"`
	Database        string  `json:"database"`
	SSHConnectionID int64   `json:"ssh_connection_id"`
}

// DependentsResponse lists profiles referencing a connection id. It is the
// warning payload shown before deletion; deletion itself is never blocked.
type DependentsResponse struct {
	SSH []DependentRef `json:"ssh"`
	DB  []DependentRef `json:"db"`
}
