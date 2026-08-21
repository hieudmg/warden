package model

// SSHNode is one hop in a resolved SSH transport bundle: the target or a
// jump host. Secret fields are decrypted plaintext, held only in server
// memory for the duration of a transport response and in the client process
// during local execution. Transport responses set Cache-Control: no-store.
type SSHNode struct {
	ID                   int64  `json:"id"`
	Name                 string `json:"name"`
	Host                 string `json:"host"`
	Port                 int    `json:"port"`
	Username             string `json:"username"`
	Password             []byte `json:"password,omitempty"`
	PrivateKey           []byte `json:"private_key,omitempty"`
	PrivateKeyPassphrase []byte `json:"private_key_passphrase,omitempty"`
	ProxyHost            string `json:"proxy_host,omitempty"`
	ProxyPort            int    `json:"proxy_port,omitempty"`
	ProxyUsername        string `json:"proxy_username,omitempty"`
	ProxyPassword        []byte `json:"proxy_password,omitempty"`
}

// SSHBundle is the complete resolved transport bundle for one SSH target:
// the target plus every jump host in connection order (first hop first).
type SSHBundle struct {
	Target SSHNode   `json:"target"`
	Jumps  []SSHNode `json:"jumps"`
}

// DBBundle is the complete resolved transport bundle for a DB profile.
// SSH is nil for direct connections and otherwise holds the full resolved
// SSH graph used to tunnel to the database.
type DBBundle struct {
	Host     string     `json:"host"`
	Port     int        `json:"port"`
	Username string     `json:"username"`
	Password []byte     `json:"password,omitempty"`
	Database string     `json:"database"`
	SSH      *SSHBundle `json:"ssh,omitempty"`
}
