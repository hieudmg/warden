package model

import "time"

// SSHProfile is the domain value for an SSH connection profile.
// Secret fields hold plaintext values in memory; the store encrypts them
// at rest with AAD bound to the row id and decrypts them on read.
type SSHProfile struct {
	ID                   int64
	Name                 string
	Host                 string
	Port                 int
	Username             string
	Password             []byte
	PrivateKey           []byte
	PrivateKeyPassphrase []byte
	ProxyHost            string
	ProxyPort            int
	ProxyUsername        string
	ProxyPassword        []byte
	// JumpConnectionIDs is the raw JSON integer-array text stored on the row,
	// e.g. `[12,4]`. Write operations validate JSON syntax only; logical
	// resolution (missing ids, self-reference, cycles) happens at
	// transport-query time.
	JumpConnectionIDs string
	// DefaultDir is an optional absolute directory on the remote host
	// that xssh prefixes to the remote shell command (`cd <dir> && exec ...`).
	// Empty means no prefix. Validation lives in store/handlers: must be
	// an absolute path with no path-traversal or control characters.
	DefaultDir        string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// DBProfile is the domain value for a MySQL/MariaDB connection profile.
// SSHConnectionID is 0 when the connection is direct and otherwise references
// an ssh_connections row. It is deliberately not a foreign key so SSH
// deletion is never blocked by DB profiles; the reference is validated at
// transport-query time.
type DBProfile struct {
	ID              int64
	Name            string
	Host            string
	Port            int
	Username        string
	Password        []byte
	Database        string
	SSHConnectionID int64
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// DependentRef identifies a profile that references another connection id.
type DependentRef struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// SSHDependents lists profiles referencing an SSH connection id: SSH
// profiles whose jump route includes it and DB profiles whose
// SSHConnectionID equals it.
type SSHDependents struct {
	SSH []DependentRef
	DB  []DependentRef
}

// GroupDependents lists profiles referencing a group id: SSH profiles and
// DB profiles whose group_id equals it. It is the warning payload shown
// before group deletion; deletion itself is never blocked.
type GroupDependents struct {
	SSH []DependentRef
	DB  []DependentRef
}
