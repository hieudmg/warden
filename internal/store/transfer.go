package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"warden/internal/model"
)

// ErrDestinationNotEmpty is returned by ImportData when the destination
// already holds any managed record. Import never modifies a non-empty store,
// so a rejected migration cannot corrupt live data.
var ErrDestinationNotEmpty = errors.New("store: destination already contains managed data")

// managedTransferTables lists every user-managed table the bundle carries.
// Import requires all of them to be empty before it writes anything. Audit
// events are operational metadata and deliberately excluded: they do not
// block a migration and are never transferred.
var managedTransferTables = []string{
	"groups",
	"key_pairs",
	"ssh_connections",
	"db_connections",
	"projects",
	"reports",
	"connection_notes",
}

// formatTransferTime renders a timestamp with the store's UTC layout so an
// exported-then-imported row keeps the exact stored representation.
func formatTransferTime(t time.Time) string {
	return t.UTC().Format(timeLayout)
}

// ExportData returns a complete snapshot of every managed record, including
// decrypted secret values. The reads run inside one transaction so the
// snapshot is internally consistent, and plaintext exists only in the returned
// in-memory bundle. Dangling soft references are exported verbatim.
func (s *Store) ExportData(ctx context.Context) (model.DataBundle, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.DataBundle{}, fmt.Errorf("begin export transaction: %w", err)
	}
	defer tx.Rollback()

	bundle := model.DataBundle{
		Format:          model.DataBundleFormat,
		Version:         model.DataBundleVersion,
		ExportedAt:      time.Now().UTC(),
		Groups:          make([]model.TransferGroup, 0),
		KeyPairs:        make([]model.TransferKeyPair, 0),
		SSHConnections:  make([]model.TransferSSHConnection, 0),
		DBConnections:   make([]model.TransferDBConnection, 0),
		Projects:        make([]model.TransferProject, 0),
		Reports:         make([]model.TransferReport, 0),
		ConnectionNotes: make([]model.TransferConnectionNote, 0),
	}

	if bundle.Groups, err = exportGroups(ctx, tx); err != nil {
		return model.DataBundle{}, err
	}
	if bundle.KeyPairs, err = s.exportKeyPairs(ctx, tx); err != nil {
		return model.DataBundle{}, err
	}
	if bundle.SSHConnections, err = s.exportSSHConnections(ctx, tx); err != nil {
		return model.DataBundle{}, err
	}
	if bundle.DBConnections, err = s.exportDBConnections(ctx, tx); err != nil {
		return model.DataBundle{}, err
	}
	if bundle.Projects, err = exportProjects(ctx, tx); err != nil {
		return model.DataBundle{}, err
	}
	if bundle.Reports, err = exportReports(ctx, tx); err != nil {
		return model.DataBundle{}, err
	}
	if bundle.ConnectionNotes, err = exportConnectionNotes(ctx, tx); err != nil {
		return model.DataBundle{}, err
	}

	return bundle, nil
}

func exportGroups(ctx context.Context, tx *sql.Tx) ([]model.TransferGroup, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT id, name, created_at, updated_at FROM groups ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("export groups: %w", err)
	}
	defer rows.Close()

	out := make([]model.TransferGroup, 0)
	for rows.Next() {
		var g model.TransferGroup
		var createdAt, updatedAt string
		if err := rows.Scan(&g.ID, &g.Name, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("scan group: %w", err)
		}
		if g.CreatedAt, err = parseTime(createdAt); err != nil {
			return nil, fmt.Errorf("parse group created_at: %w", err)
		}
		if g.UpdatedAt, err = parseTime(updatedAt); err != nil {
			return nil, fmt.Errorf("parse group updated_at: %w", err)
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) exportKeyPairs(ctx context.Context, tx *sql.Tx) ([]model.TransferKeyPair, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT id, name, public_key, private_key, private_key_passphrase,
		       created_at, updated_at
		FROM key_pairs ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("export key_pairs: %w", err)
	}
	defer rows.Close()

	out := make([]model.TransferKeyPair, 0)
	for rows.Next() {
		var p model.TransferKeyPair
		var storedPublic, storedPrivate, storedPassphrase []byte
		var createdAt, updatedAt string
		if err := rows.Scan(&p.ID, &p.Name, &storedPublic, &storedPrivate,
			&storedPassphrase, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("scan key_pair: %w", err)
		}

		publicKey, err := s.decryptSecret(keyPairAAD(p.ID, "public_key"), storedPublic)
		if err != nil {
			return nil, fmt.Errorf("decrypt public key for %d: %w", p.ID, err)
		}
		privateKey, err := s.decryptSecret(keyPairAAD(p.ID, "private_key"), storedPrivate)
		if err != nil {
			return nil, fmt.Errorf("decrypt private key for %d: %w", p.ID, err)
		}
		passphrase, err := s.decryptSecret(keyPairAAD(p.ID, "private_key_passphrase"), storedPassphrase)
		if err != nil {
			return nil, fmt.Errorf("decrypt passphrase for %d: %w", p.ID, err)
		}

		p.PublicKey = string(publicKey)
		p.PrivateKey = string(privateKey)
		p.PrivateKeyPassphrase = string(passphrase)
		if p.CreatedAt, err = parseTime(createdAt); err != nil {
			return nil, fmt.Errorf("parse key_pair created_at: %w", err)
		}
		if p.UpdatedAt, err = parseTime(updatedAt); err != nil {
			return nil, fmt.Errorf("parse key_pair updated_at: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) exportSSHConnections(ctx context.Context, tx *sql.Tx) ([]model.TransferSSHConnection, error) {
	// proxy_host/proxy_port/proxy_username are nullable in the schema, so
	// COALESCE them to their zero values; every other column is NOT NULL.
	// Notes are exported separately from the connection_notes table so rows
	// whose reference is missing, empty, or an unrecognized type survive too.
	rows, err := tx.QueryContext(ctx, `
		SELECT s.id, s.name, s.host, s.port, s.username, s.password,
		       COALESCE(s.proxy_host, ''), COALESCE(s.proxy_port, 0),
		       COALESCE(s.proxy_username, ''), s.proxy_password,
		       s.jump_connection_ids, s.default_dir, s.group_id, s.key_pair_id,
		       s.created_at, s.updated_at
		FROM ssh_connections s
		ORDER BY s.id`)
	if err != nil {
		return nil, fmt.Errorf("export ssh_connections: %w", err)
	}
	defer rows.Close()

	out := make([]model.TransferSSHConnection, 0)
	for rows.Next() {
		var c model.TransferSSHConnection
		var password, proxyPassword []byte
		var createdAt, updatedAt string
		if err := rows.Scan(&c.ID, &c.Name, &c.Host, &c.Port, &c.Username, &password,
			&c.ProxyHost, &c.ProxyPort, &c.ProxyUsername, &proxyPassword,
			&c.JumpConnectionIDs, &c.DefaultDir, &c.GroupID, &c.KeyPairID,
			&createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("scan ssh_connection: %w", err)
		}

		plainPassword, err := s.decryptSecret(sshAAD(c.ID, "password"), password)
		if err != nil {
			return nil, fmt.Errorf("decrypt password for %d: %w", c.ID, err)
		}
		plainProxyPassword, err := s.decryptSecret(sshAAD(c.ID, "proxy_password"), proxyPassword)
		if err != nil {
			return nil, fmt.Errorf("decrypt proxy password for %d: %w", c.ID, err)
		}
		c.Password = string(plainPassword)
		c.ProxyPassword = string(plainProxyPassword)

		if c.CreatedAt, err = parseTime(createdAt); err != nil {
			return nil, fmt.Errorf("parse ssh_connection created_at: %w", err)
		}
		if c.UpdatedAt, err = parseTime(updatedAt); err != nil {
			return nil, fmt.Errorf("parse ssh_connection updated_at: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) exportDBConnections(ctx context.Context, tx *sql.Tx) ([]model.TransferDBConnection, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT d.id, d.name, d.host, d.port, d.username, d.password, d.database,
		       d.ssh_connection_id, d.group_id, d.created_at, d.updated_at
		FROM db_connections d
		ORDER BY d.id`)
	if err != nil {
		return nil, fmt.Errorf("export db_connections: %w", err)
	}
	defer rows.Close()

	out := make([]model.TransferDBConnection, 0)
	for rows.Next() {
		var c model.TransferDBConnection
		var password []byte
		var storedDatabases, createdAt, updatedAt string
		if err := rows.Scan(&c.ID, &c.Name, &c.Host, &c.Port, &c.Username, &password,
			&storedDatabases, &c.SSHConnectionID, &c.GroupID,
			&createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("scan db_connection: %w", err)
		}

		if c.Databases, err = decodeDatabases(storedDatabases); err != nil {
			return nil, fmt.Errorf("decode databases for %d: %w", c.ID, err)
		}
		plainPassword, err := s.decryptSecret(dbAAD(c.ID, "password"), password)
		if err != nil {
			return nil, fmt.Errorf("decrypt password for %d: %w", c.ID, err)
		}
		c.Password = string(plainPassword)

		if c.CreatedAt, err = parseTime(createdAt); err != nil {
			return nil, fmt.Errorf("parse db_connection created_at: %w", err)
		}
		if c.UpdatedAt, err = parseTime(updatedAt); err != nil {
			return nil, fmt.Errorf("parse db_connection updated_at: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func exportProjects(ctx context.Context, tx *sql.Tx) ([]model.TransferProject, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id, name FROM projects ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("export projects: %w", err)
	}
	defer rows.Close()

	out := make([]model.TransferProject, 0)
	for rows.Next() {
		var p model.TransferProject
		if err := rows.Scan(&p.ID, &p.Name); err != nil {
			return nil, fmt.Errorf("scan project: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func exportReports(ctx context.Context, tx *sql.Tx) ([]model.TransferReport, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT id, project_id, title, summary, agent_model, created_at
		FROM reports ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("export reports: %w", err)
	}
	defer rows.Close()

	out := make([]model.TransferReport, 0)
	for rows.Next() {
		var r model.TransferReport
		var createdAt string
		if err := rows.Scan(&r.ID, &r.ProjectID, &r.Title, &r.Summary,
			&r.AgentModel, &createdAt); err != nil {
			return nil, fmt.Errorf("scan report: %w", err)
		}
		if r.CreatedAt, err = parseTime(createdAt); err != nil {
			return nil, fmt.Errorf("parse report created_at: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// exportConnectionNotes reads every persisted connection_notes row verbatim,
// including empty notes, rows whose connection is missing, and rows whose
// connection_type is unrecognized. The table has no foreign key, so only the
// raw table dump can preserve all of it.
func exportConnectionNotes(ctx context.Context, tx *sql.Tx) ([]model.TransferConnectionNote, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT connection_type, connection_id, note
		FROM connection_notes
		ORDER BY connection_type, connection_id`)
	if err != nil {
		return nil, fmt.Errorf("export connection_notes: %w", err)
	}
	defer rows.Close()

	out := make([]model.TransferConnectionNote, 0)
	for rows.Next() {
		var n model.TransferConnectionNote
		if err := rows.Scan(&n.ConnectionType, &n.ConnectionID, &n.Note); err != nil {
			return nil, fmt.Errorf("scan connection_note: %w", err)
		}
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// ImportData restores a bundle into an empty store. The whole restore is one
// transaction: validation runs first, the destination must hold no managed
// record, every id and timestamp is preserved, and every secret is re-encrypted
// with this store's master key and its row-bound AAD. Dangling soft references
// (group ids, key-pair ids, jump ids, DB tunnel ids) are preserved exactly as
// supplied; only the hard report-to-project link is enforced.
func (s *Store) ImportData(ctx context.Context, bundle model.DataBundle) error {
	if err := validateDataBundle(bundle); err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin import transaction: %w", err)
	}
	defer tx.Rollback()

	if err := requireEmptyDestination(ctx, tx); err != nil {
		return err
	}

	if err := insertGroups(ctx, tx, bundle.Groups); err != nil {
		return err
	}
	if err := s.insertKeyPairs(ctx, tx, bundle.KeyPairs); err != nil {
		return err
	}
	if err := s.insertSSHConnections(ctx, tx, bundle.SSHConnections); err != nil {
		return err
	}
	if err := s.insertDBConnections(ctx, tx, bundle.DBConnections); err != nil {
		return err
	}
	if err := insertProjects(ctx, tx, bundle.Projects); err != nil {
		return err
	}
	if err := insertReports(ctx, tx, bundle.Reports); err != nil {
		return err
	}
	if err := insertConnectionNotes(ctx, tx, bundle.ConnectionNotes); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit import: %w", err)
	}
	return nil
}

// requireEmptyDestination re-checks every managed table inside the write
// transaction so a concurrent import cannot slip past the pre-check.
func requireEmptyDestination(ctx context.Context, tx *sql.Tx) error {
	for _, table := range managedTransferTables {
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&count); err != nil {
			return fmt.Errorf("count %s: %w", table, err)
		}
		if count > 0 {
			return fmt.Errorf("%w: %s holds %d record(s)", ErrDestinationNotEmpty, table, count)
		}
	}
	return nil
}

// validateDataBundle validates the entire bundle before any mutation. Only the
// report-to-project link is treated as a hard constraint; soft references are
// validated for syntax and sign only.
func validateDataBundle(b model.DataBundle) error {
	if b.Format != model.DataBundleFormat {
		return fmt.Errorf("%w: unsupported bundle format %q", ErrValidation, b.Format)
	}
	if b.Version != model.DataBundleVersion {
		return fmt.Errorf("%w: unsupported bundle version %d", ErrValidation, b.Version)
	}
	if b.ExportedAt.IsZero() {
		return fmt.Errorf("%w: exported_at is missing", ErrValidation)
	}
	if b.Groups == nil || b.KeyPairs == nil || b.SSHConnections == nil ||
		b.DBConnections == nil || b.Projects == nil || b.Reports == nil || b.ConnectionNotes == nil {
		return fmt.Errorf("%w: bundle must include every record collection", ErrValidation)
	}

	groupIDs := make(map[int64]struct{}, len(b.Groups))
	groupNames := make(map[string]struct{}, len(b.Groups))
	for _, g := range b.Groups {
		if err := claimTransferID("group", g.ID, groupIDs); err != nil {
			return err
		}
		name, err := normalizeGroupName(g.Name)
		if err != nil {
			return err
		}
		if _, dup := groupNames[name]; dup {
			return fmt.Errorf("%w: duplicate group name %q", ErrValidation, name)
		}
		groupNames[name] = struct{}{}
		if err := validateTransferTimestamps("group", g.CreatedAt, g.UpdatedAt); err != nil {
			return err
		}
	}

	keyPairIDs := make(map[int64]struct{}, len(b.KeyPairs))
	keyPairNames := make(map[string]struct{}, len(b.KeyPairs))
	for _, p := range b.KeyPairs {
		if err := claimTransferID("key pair", p.ID, keyPairIDs); err != nil {
			return err
		}
		name, err := normalizeGroupName(p.Name)
		if err != nil {
			return err
		}
		if _, dup := keyPairNames[name]; dup {
			return fmt.Errorf("%w: duplicate key pair name %q", ErrValidation, name)
		}
		keyPairNames[name] = struct{}{}
		if err := validateTransferTimestamps("key pair", p.CreatedAt, p.UpdatedAt); err != nil {
			return err
		}
	}

	sshIDs := make(map[int64]struct{}, len(b.SSHConnections))
	sshNames := make(map[string]struct{}, len(b.SSHConnections))
	for _, c := range b.SSHConnections {
		if err := claimTransferID("ssh connection", c.ID, sshIDs); err != nil {
			return err
		}
		if _, dup := sshNames[c.Name]; dup {
			return fmt.Errorf("%w: duplicate ssh connection name %q", ErrValidation, c.Name)
		}
		sshNames[c.Name] = struct{}{}
		if err := validateJumpIDs(c.JumpConnectionIDs); err != nil {
			return fmt.Errorf("%w: %v", ErrValidation, err)
		}
		if err := validateSSHMetadata(model.SSHProfile{
			Name:          c.Name,
			Host:          c.Host,
			Port:          c.Port,
			Username:      c.Username,
			ProxyHost:     c.ProxyHost,
			ProxyPort:     c.ProxyPort,
			ProxyUsername: c.ProxyUsername,
			DefaultDir:    c.DefaultDir,
		}); err != nil {
			return fmt.Errorf("%w: %v", ErrValidation, err)
		}
		// Password and key_pair_id are mutually exclusive on the live write
		// path; reject bundles that would create a row the API never accepts.
		// A key-pair reference with an empty password, including a dangling
		// one, stays valid and is preserved as supplied.
		if c.Password != "" && c.KeyPairID != 0 {
			return fmt.Errorf("%w: ssh connection %d password and key_pair_id are mutually exclusive", ErrValidation, c.ID)
		}
		if c.GroupID < 0 {
			return fmt.Errorf("%w: ssh connection %d group_id must not be negative", ErrValidation, c.ID)
		}
		if c.KeyPairID < 0 {
			return fmt.Errorf("%w: ssh connection %d key_pair_id must not be negative", ErrValidation, c.ID)
		}
		if err := validateTransferTimestamps("ssh connection", c.CreatedAt, c.UpdatedAt); err != nil {
			return err
		}
	}

	dbIDs := make(map[int64]struct{}, len(b.DBConnections))
	dbNames := make(map[string]struct{}, len(b.DBConnections))
	for _, c := range b.DBConnections {
		if err := claimTransferID("db connection", c.ID, dbIDs); err != nil {
			return err
		}
		if _, dup := dbNames[c.Name]; dup {
			return fmt.Errorf("%w: duplicate db connection name %q", ErrValidation, c.Name)
		}
		dbNames[c.Name] = struct{}{}
		if err := validateDBMetadata(model.DBProfile{
			Name:            c.Name,
			Host:            c.Host,
			Port:            c.Port,
			Username:        c.Username,
			Databases:       c.Databases,
			SSHConnectionID: c.SSHConnectionID,
		}); err != nil {
			return fmt.Errorf("%w: %v", ErrValidation, err)
		}
		if c.GroupID < 0 {
			return fmt.Errorf("%w: db connection %d group_id must not be negative", ErrValidation, c.ID)
		}
		if err := validateTransferTimestamps("db connection", c.CreatedAt, c.UpdatedAt); err != nil {
			return err
		}
	}

	projectIDs := make(map[int64]struct{}, len(b.Projects))
	projectNames := make(map[string]struct{}, len(b.Projects))
	for _, p := range b.Projects {
		if err := claimTransferID("project", p.ID, projectIDs); err != nil {
			return err
		}
		if err := validateProjectName(p.Name); err != nil {
			return fmt.Errorf("%w: %v", ErrValidation, err)
		}
		if _, dup := projectNames[p.Name]; dup {
			return fmt.Errorf("%w: duplicate project name %q", ErrValidation, p.Name)
		}
		projectNames[p.Name] = struct{}{}
	}

	reportIDs := make(map[int64]struct{}, len(b.Reports))
	for _, r := range b.Reports {
		if err := claimTransferID("report", r.ID, reportIDs); err != nil {
			return err
		}
		if _, ok := projectIDs[r.ProjectID]; !ok {
			return fmt.Errorf("%w: report %d references unknown project %d", ErrValidation, r.ID, r.ProjectID)
		}
		if err := validateReportFields(r.Title, r.Summary, r.AgentModel); err != nil {
			return fmt.Errorf("%w: %v", ErrValidation, err)
		}
		if r.CreatedAt.IsZero() {
			return fmt.Errorf("%w: report %d created_at is missing", ErrValidation, r.ID)
		}
	}

	// connection_notes has a UNIQUE (connection_type, connection_id) key, so a
	// duplicate pair cannot be inserted. Reject it before any write instead of
	// failing partway through the transaction. Content is preserved verbatim:
	// empty notes, orphaned rows, and unrecognized types are all valid.
	noteKeys := make(map[transferNoteKey]struct{}, len(b.ConnectionNotes))
	for _, n := range b.ConnectionNotes {
		key := transferNoteKey{connectionType: n.ConnectionType, connectionID: n.ConnectionID}
		if _, dup := noteKeys[key]; dup {
			return fmt.Errorf("%w: duplicate connection note for type %q id %d", ErrValidation, n.ConnectionType, n.ConnectionID)
		}
		noteKeys[key] = struct{}{}
	}

	return nil
}

// transferNoteKey is the natural key of one connection_notes row, used only
// for duplicate detection while validating an import bundle.
type transferNoteKey struct {
	connectionType string
	connectionID   int64
}

func claimTransferID(kind string, id int64, seen map[int64]struct{}) error {
	if id <= 0 {
		return fmt.Errorf("%w: %s id %d must be positive", ErrValidation, kind, id)
	}
	if _, dup := seen[id]; dup {
		return fmt.Errorf("%w: duplicate %s id %d", ErrValidation, kind, id)
	}
	seen[id] = struct{}{}
	return nil
}

func validateTransferTimestamps(kind string, createdAt, updatedAt time.Time) error {
	if createdAt.IsZero() {
		return fmt.Errorf("%w: %s created_at is missing", ErrValidation, kind)
	}
	if updatedAt.IsZero() {
		return fmt.Errorf("%w: %s updated_at is missing", ErrValidation, kind)
	}
	return nil
}

func insertGroups(ctx context.Context, tx *sql.Tx, groups []model.TransferGroup) error {
	for _, g := range groups {
		name, err := normalizeGroupName(g.Name)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO groups (id, name, created_at, updated_at)
			VALUES (?, ?, ?, ?)`,
			g.ID, name, formatTransferTime(g.CreatedAt), formatTransferTime(g.UpdatedAt)); err != nil {
			return fmt.Errorf("insert group %d: %w", g.ID, err)
		}
	}
	return nil
}

func (s *Store) insertKeyPairs(ctx context.Context, tx *sql.Tx, keyPairs []model.TransferKeyPair) error {
	for _, p := range keyPairs {
		name, err := normalizeGroupName(p.Name)
		if err != nil {
			return err
		}
		publicKey, err := s.encryptSecret(keyPairAAD(p.ID, "public_key"), []byte(p.PublicKey))
		if err != nil {
			return fmt.Errorf("encrypt public key %d: %w", p.ID, err)
		}
		privateKey, err := s.encryptSecret(keyPairAAD(p.ID, "private_key"), []byte(p.PrivateKey))
		if err != nil {
			return fmt.Errorf("encrypt private key %d: %w", p.ID, err)
		}
		passphrase, err := s.encryptSecret(keyPairAAD(p.ID, "private_key_passphrase"), []byte(p.PrivateKeyPassphrase))
		if err != nil {
			return fmt.Errorf("encrypt passphrase %d: %w", p.ID, err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO key_pairs
				(id, name, public_key, private_key, private_key_passphrase, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			p.ID, name, publicKey, privateKey, passphrase,
			formatTransferTime(p.CreatedAt), formatTransferTime(p.UpdatedAt)); err != nil {
			return fmt.Errorf("insert key pair %d: %w", p.ID, err)
		}
	}
	return nil
}

func (s *Store) insertSSHConnections(ctx context.Context, tx *sql.Tx, connections []model.TransferSSHConnection) error {
	for _, c := range connections {
		password, err := s.encryptSecret(sshAAD(c.ID, "password"), []byte(c.Password))
		if err != nil {
			return fmt.Errorf("encrypt password %d: %w", c.ID, err)
		}
		proxyPassword, err := s.encryptSecret(sshAAD(c.ID, "proxy_password"), []byte(c.ProxyPassword))
		if err != nil {
			return fmt.Errorf("encrypt proxy password %d: %w", c.ID, err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO ssh_connections
				(id, name, host, port, username, password, proxy_host, proxy_port,
				 proxy_username, proxy_password, jump_connection_ids, default_dir,
				 group_id, key_pair_id, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			c.ID, c.Name, c.Host, c.Port, c.Username, password, c.ProxyHost, c.ProxyPort,
			c.ProxyUsername, proxyPassword, c.JumpConnectionIDs, c.DefaultDir,
			c.GroupID, c.KeyPairID,
			formatTransferTime(c.CreatedAt), formatTransferTime(c.UpdatedAt)); err != nil {
			return fmt.Errorf("insert ssh connection %d: %w", c.ID, err)
		}
	}
	return nil
}

func (s *Store) insertDBConnections(ctx context.Context, tx *sql.Tx, connections []model.TransferDBConnection) error {
	for _, c := range connections {
		databases, err := encodeDatabases(c.Databases)
		if err != nil {
			return fmt.Errorf("%w: db connection %d: %v", ErrValidation, c.ID, err)
		}
		password, err := s.encryptSecret(dbAAD(c.ID, "password"), []byte(c.Password))
		if err != nil {
			return fmt.Errorf("encrypt password %d: %w", c.ID, err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO db_connections
				(id, name, host, port, username, password, database,
				 ssh_connection_id, group_id, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			c.ID, c.Name, c.Host, c.Port, c.Username, password, databases,
			c.SSHConnectionID, c.GroupID,
			formatTransferTime(c.CreatedAt), formatTransferTime(c.UpdatedAt)); err != nil {
			return fmt.Errorf("insert db connection %d: %w", c.ID, err)
		}
	}
	return nil
}

func insertProjects(ctx context.Context, tx *sql.Tx, projects []model.TransferProject) error {
	for _, p := range projects {
		if _, err := tx.ExecContext(ctx, `INSERT INTO projects (id, name) VALUES (?, ?)`,
			p.ID, p.Name); err != nil {
			return fmt.Errorf("insert project %d: %w", p.ID, err)
		}
	}
	return nil
}

func insertReports(ctx context.Context, tx *sql.Tx, reports []model.TransferReport) error {
	for _, r := range reports {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO reports (id, project_id, title, summary, agent_model, created_at)
			VALUES (?, ?, ?, ?, ?, ?)`,
			r.ID, r.ProjectID, r.Title, r.Summary, r.AgentModel,
			formatTransferTime(r.CreatedAt)); err != nil {
			return fmt.Errorf("insert report %d: %w", r.ID, err)
		}
	}
	return nil
}

// insertConnectionNotes restores every connection_notes row verbatim. The
// (connection_type, connection_id) pair is the table's natural key and the
// bundle has already been checked for duplicates; the note text is written
// unchanged so empty, orphaned, and unrecognized-type rows all survive.
func insertConnectionNotes(ctx context.Context, tx *sql.Tx, notes []model.TransferConnectionNote) error {
	for _, n := range notes {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO connection_notes (connection_type, connection_id, note)
			VALUES (?, ?, ?)`,
			n.ConnectionType, n.ConnectionID, n.Note); err != nil {
			return fmt.Errorf("insert connection note for type %q id %d: %w", n.ConnectionType, n.ConnectionID, err)
		}
	}
	return nil
}
