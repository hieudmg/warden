package model

import "time"

// SSHConnection is the redacted API representation of an SSH profile.
// Secret values are never serialized; Has* booleans report presence so the
// UI/CLI can show "password set" without exposing the value. KeyPairID
// references a stored key pair when nonzero and KeyPairName is the
// display-only pair name (empty when the reference is dangling).
type SSHConnection struct {
	ID                int64     `json:"id"`
	Name              string    `json:"name"`
	Host              string    `json:"host"`
	Port              int       `json:"port"`
	Username          string    `json:"username"`
	HasPassword       bool      `json:"has_password"`
	KeyPairID         int64     `json:"key_pair_id"`
	KeyPairName       string    `json:"key_pair_name,omitempty"`
	ProxyHost         string    `json:"proxy_host,omitempty"`
	ProxyPort         int       `json:"proxy_port,omitempty"`
	ProxyUsername     string    `json:"proxy_username,omitempty"`
	HasProxyPassword  bool      `json:"has_proxy_password"`
	JumpConnectionIDs string    `json:"jump_connection_ids"`
	DefaultDir        string    `json:"default_dir"`
	GroupID           int64     `json:"group_id"`
	GroupName         string    `json:"group_name,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
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
	GroupID         int64     `json:"group_id"`
	GroupName       string    `json:"group_name,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// SSHConnectionRequest is the write payload for creating/updating an SSH
// profile. Secret fields are pointers: nil means "not provided" (keep the
// stored value on update, store nothing on create); non-nil replaces.
// KeyPairID selects a stored key pair; 0 means no stored pair selected.
type SSHConnectionRequest struct {
	Name              string  `json:"name"`
	Host              string  `json:"host"`
	Port              int     `json:"port"`
	Username          string  `json:"username"`
	Password          *string `json:"password"`
	KeyPairID         int64   `json:"key_pair_id"`
	ProxyHost         string  `json:"proxy_host"`
	ProxyPort         int     `json:"proxy_port"`
	ProxyUsername     string  `json:"proxy_username"`
	ProxyPassword     *string `json:"proxy_password"`
	JumpConnectionIDs string  `json:"jump_connection_ids"`
	DefaultDir        string  `json:"default_dir"`
	GroupID           int64   `json:"group_id"`
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
	GroupID         int64   `json:"group_id"`
}

// DependentsResponse lists profiles referencing a connection id. It is the
// warning payload shown before deletion; deletion itself is never blocked.
type DependentsResponse struct {
	SSH []DependentRef `json:"ssh"`
	DB  []DependentRef `json:"db"`
}

// Group is both the domain and the non-secret API representation of a
// connection group shared by SSH and DB profiles. Groups need no separate
// redacted view: they hold no secret data. SSHConnectionCount and
// DBConnectionCount report how many profiles reference the group and are
// zero for a newly created group.
type Group struct {
	ID                 int64     `json:"id"`
	Name               string    `json:"name"`
	SSHConnectionCount int       `json:"ssh_connection_count"`
	DBConnectionCount  int       `json:"db_connection_count"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// GroupRequest is the write payload for creating/renaming a group.
type GroupRequest struct {
	Name string `json:"name"`
}

// KeyPairVault is the single-pair API view returned by an individual vault
// GET. It intentionally uses string values so the client receives raw
// public/private/passphrase material for view/edit, unlike the redacted
// list view. This is the sole API response that discloses key material.
type KeyPairVault struct {
	ID                   int64     `json:"id"`
	Name                 string    `json:"name"`
	PublicKey            string    `json:"public_key"`
	PrivateKey           string    `json:"private_key"`
	PrivateKeyPassphrase string    `json:"private_key_passphrase"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

// KeyPairRequest is the write payload for creating/updating a key pair.
// Secret fields are pointers so omission on update retains the stored
// value: nil means "not provided" (keep), non-nil empty string means
// "explicitly clear".
type KeyPairRequest struct {
	Name                 string  `json:"name"`
	PublicKey            *string `json:"public_key"`
	PrivateKey           *string `json:"private_key"`
	PrivateKeyPassphrase *string `json:"private_key_passphrase"`
}
