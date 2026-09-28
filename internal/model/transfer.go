package model

import "time"

// Data bundle identity. An importer rejects any other format or version, so
// the exported shape can evolve only by bumping DataBundleVersion.
const (
	DataBundleFormat  = "warden-data"
	DataBundleVersion = 1
)

// DataBundle is the portable, unencrypted snapshot exchanged by the web
// export/import migration flow. It carries every user-managed record with
// original ids and timestamps so cross-record references survive the move.
// Internal audit history and server configuration are deliberately excluded.
//
// Secret fields are plaintext strings here: the bundle leaves the server as
// an unencrypted file, and the importing server re-encrypts each value under
// its own master key. Transfer records carry no computed display fields
// (group names, connection counts), only stored data.
type DataBundle struct {
	Format     string    `json:"format"`
	Version    int       `json:"version"`
	ExportedAt time.Time `json:"exported_at"`

	Groups         []TransferGroup         `json:"groups"`
	KeyPairs       []TransferKeyPair       `json:"key_pairs"`
	SSHConnections []TransferSSHConnection `json:"ssh_connections"`
	DBConnections  []TransferDBConnection  `json:"db_connections"`
	Projects       []TransferProject       `json:"projects"`
	Reports        []TransferReport        `json:"reports"`
	// ConnectionNotes carries every persisted connection_notes row verbatim.
	// It is the single source of truth for notes: attachment to a profile is
	// implied by (connection_type, connection_id), and rows whose reference is
	// missing, empty, or an unrecognized type are preserved exactly. Notes are
	// deliberately not duplicated inside the profile records above.
	ConnectionNotes []TransferConnectionNote `json:"connection_notes"`
}

// TransferConnectionNote is one stored connection_notes row. ConnectionType
// and ConnectionID form the row's natural key; the importer rejects duplicate
// pairs because the table's UNIQUE constraint makes them unrecoverable.
type TransferConnectionNote struct {
	ConnectionType string `json:"connection_type"`
	ConnectionID   int64  `json:"connection_id"`
	Note           string `json:"note"`
}

// TransferGroup is the stored form of a connection group. Counts are derived
// on read and are not part of the transfer.
type TransferGroup struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TransferKeyPair carries full key-pair material, including the private key
// and passphrase, because the destination must be able to serve connections
// that reference the pair.
type TransferKeyPair struct {
	ID                   int64     `json:"id"`
	Name                 string    `json:"name"`
	PublicKey            string    `json:"public_key"`
	PrivateKey           string    `json:"private_key"`
	PrivateKeyPassphrase string    `json:"private_key_passphrase"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

// TransferSSHConnection carries an SSH profile with its decrypted secrets and
// its raw stored references. GroupID, KeyPairID, and JumpConnectionIDs may be
// dangling; the importer preserves them exactly as stored. Notes are not
// carried here: every connection_notes row travels in the bundle's top-level
// ConnectionNotes collection.
type TransferSSHConnection struct {
	ID                int64     `json:"id"`
	Name              string    `json:"name"`
	Host              string    `json:"host"`
	Port              int       `json:"port"`
	Username          string    `json:"username"`
	Password          string    `json:"password"`
	ProxyHost         string    `json:"proxy_host"`
	ProxyPort         int       `json:"proxy_port"`
	ProxyUsername     string    `json:"proxy_username"`
	ProxyPassword     string    `json:"proxy_password"`
	JumpConnectionIDs string    `json:"jump_connection_ids"`
	DefaultDir        string    `json:"default_dir"`
	GroupID           int64     `json:"group_id"`
	KeyPairID         int64     `json:"key_pair_id"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// TransferDBConnection carries a database profile with its decrypted password,
// canonical database list, and raw stored references. SSHConnectionID and
// GroupID may be dangling. Notes travel in the top-level ConnectionNotes
// collection, not here.
type TransferDBConnection struct {
	ID              int64          `json:"id"`
	Name            string         `json:"name"`
	Host            string         `json:"host"`
	Port            int            `json:"port"`
	Username        string         `json:"username"`
	Password        string         `json:"password"`
	Databases       []DatabaseInfo `json:"databases"`
	SSHConnectionID int64          `json:"ssh_connection_id"`
	GroupID         int64          `json:"group_id"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

// TransferProject preserves the project id that reports reference.
type TransferProject struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// TransferReport preserves the report id, its project reference, and the
// server-assigned created_at timestamp.
type TransferReport struct {
	ID         int64     `json:"id"`
	ProjectID  int64     `json:"project_id"`
	Title      string    `json:"title"`
	Summary    string    `json:"summary"`
	AgentModel string    `json:"agent_model"`
	CreatedAt  time.Time `json:"created_at"`
}
