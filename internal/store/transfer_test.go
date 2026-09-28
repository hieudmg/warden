package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"warden/internal/model"
)

// transferSourceKey and transferDestKey are distinct 32-byte master keys used
// to prove that imported secrets are re-encrypted under the destination key
// rather than copied as ciphertext.
var (
	transferSourceKey = [32]byte{0xA1, 0x02}
	transferDestKey   = [32]byte{0xB2, 0x03}
)

// newStoreWithKey opens a migrated store with an explicit master key.
func newStoreWithKey(t *testing.T, key [32]byte) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "warden.db")
	s, err := Open(context.Background(), path, key)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

type transferFixture struct {
	groupA           model.Group
	groupB           model.Group
	keyPair          model.KeyPair
	plainKeyPair     model.KeyPair
	sshMain          model.SSHProfile
	sshKeyed         model.SSHProfile
	sshDangling      model.SSHProfile
	dbMain           model.DBProfile
	dbDanglingTunnel model.DBProfile
	project          model.Project
	report           model.Report
}

// seedTransferSource populates a store with every managed record kind,
// including notes, proxy settings, secret material, and deliberately dangling
// soft references written through raw SQL (the write path refuses to create
// them, so real stores only gain them through later deletions).
func seedTransferSource(t *testing.T, s *Store) transferFixture {
	t.Helper()
	ctx := context.Background()

	groupA, err := s.CreateGroup(ctx, model.Group{Name: "prod"})
	if err != nil {
		t.Fatalf("CreateGroup prod: %v", err)
	}
	groupB, err := s.CreateGroup(ctx, model.Group{Name: "staging"})
	if err != nil {
		t.Fatalf("CreateGroup staging: %v", err)
	}

	keyPair, err := s.CreateKeyPair(ctx, model.KeyPair{
		Name:                 "deploy-key",
		PublicKey:            []byte("public-key-material"),
		PrivateKey:           []byte("private-key-material"),
		PrivateKeyPassphrase: []byte("passphrase-material"),
	})
	if err != nil {
		t.Fatalf("CreateKeyPair: %v", err)
	}
	plainKeyPair, err := s.CreateKeyPair(ctx, model.KeyPair{
		Name:       "plain-key",
		PrivateKey: []byte("only-private-material"),
	})
	if err != nil {
		t.Fatalf("CreateKeyPair plain: %v", err)
	}

	sshMain, err := s.CreateSSH(ctx, model.SSHProfile{
		Name:              "main",
		Note:              "primary ssh",
		Host:              "main.invalid",
		Port:              22,
		Username:          "deploy",
		Password:          []byte("ssh-secret"),
		ProxyHost:         "proxy.invalid",
		ProxyPort:         1080,
		ProxyUsername:     "proxyuser",
		ProxyPassword:     []byte("proxy-secret"),
		JumpConnectionIDs: "[]",
		DefaultDir:        "/srv/app",
		GroupID:           groupA.ID,
	})
	if err != nil {
		t.Fatalf("CreateSSH main: %v", err)
	}
	sshKeyed, err := s.CreateSSH(ctx, model.SSHProfile{
		Name:              "keyed",
		Note:              "keyed host",
		Host:              "keyed.invalid",
		Port:              22,
		Username:          "deploy",
		KeyPairID:         keyPair.ID,
		JumpConnectionIDs: fmt.Sprintf("[%d]", sshMain.ID),
		GroupID:           groupB.ID,
	})
	if err != nil {
		t.Fatalf("CreateSSH keyed: %v", err)
	}
	sshDangling, err := s.CreateSSH(ctx, model.SSHProfile{
		Name:              "dangling",
		Note:              "dangling refs",
		Host:              "dangling.invalid",
		Port:              22,
		Username:          "deploy",
		JumpConnectionIDs: "[]",
	})
	if err != nil {
		t.Fatalf("CreateSSH dangling: %v", err)
	}
	if _, err := s.db.ExecContext(ctx,
		"UPDATE ssh_connections SET key_pair_id=999, group_id=999, jump_connection_ids='[999]' WHERE id=?",
		sshDangling.ID); err != nil {
		t.Fatalf("make ssh refs dangle: %v", err)
	}

	dbMain, err := s.CreateDB(ctx, model.DBProfile{
		Name:            "appdb",
		Note:            "primary db",
		Host:            "db.invalid",
		Port:            3306,
		Username:        "app",
		Password:        []byte("db-secret"),
		Databases:       []model.DatabaseInfo{{Name: "app", IsDefault: true}, {Name: "analytics"}},
		SSHConnectionID: sshMain.ID,
		GroupID:         groupB.ID,
	})
	if err != nil {
		t.Fatalf("CreateDB main: %v", err)
	}
	dbDanglingTunnel, err := s.CreateDB(ctx, model.DBProfile{
		Name:      "danglingdb",
		Host:      "db2.invalid",
		Port:      3306,
		Username:  "app",
		Databases: []model.DatabaseInfo{{Name: "app", IsDefault: true}},
	})
	if err != nil {
		t.Fatalf("CreateDB dangling: %v", err)
	}
	if _, err := s.db.ExecContext(ctx,
		"UPDATE db_connections SET ssh_connection_id=999 WHERE id=?", dbDanglingTunnel.ID); err != nil {
		t.Fatalf("make db tunnel dangle: %v", err)
	}

	project, err := s.CreateProject(ctx, "alpha")
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	report, err := s.CreateReport(ctx, "alpha", "Shipped 1.0", "Release summary text", "gpt-4o")
	if err != nil {
		t.Fatalf("CreateReport: %v", err)
	}

	if err := s.AppendAudit(ctx, model.AuditEvent{
		Operation: "test.seed", ResourceType: "test", ResourceID: "1", Source: "test", Result: "success",
	}); err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}

	return transferFixture{
		groupA:           groupA,
		groupB:           groupB,
		keyPair:          keyPair,
		plainKeyPair:     plainKeyPair,
		sshMain:          sshMain,
		sshKeyed:         sshKeyed,
		sshDangling:      sshDangling,
		dbMain:           dbMain,
		dbDanglingTunnel: dbDanglingTunnel,
		project:          project,
		report:           report,
	}
}

func bundleSSH(t *testing.T, b model.DataBundle, id int64) model.TransferSSHConnection {
	t.Helper()
	for _, c := range b.SSHConnections {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("ssh connection %d missing from bundle", id)
	return model.TransferSSHConnection{}
}

func bundleDB(t *testing.T, b model.DataBundle, id int64) model.TransferDBConnection {
	t.Helper()
	for _, c := range b.DBConnections {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("db connection %d missing from bundle", id)
	return model.TransferDBConnection{}
}

func bundleKeyPair(t *testing.T, b model.DataBundle, id int64) model.TransferKeyPair {
	t.Helper()
	for _, p := range b.KeyPairs {
		if p.ID == id {
			return p
		}
	}
	t.Fatalf("key pair %d missing from bundle", id)
	return model.TransferKeyPair{}
}

// bundleNote returns the note text carried for one (type, id) pair. Notes are
// stored in the bundle's top-level ConnectionNotes collection, not on the
// profile records.
func bundleNote(t *testing.T, b model.DataBundle, connectionType string, id int64) string {
	t.Helper()
	for _, n := range b.ConnectionNotes {
		if n.ConnectionType == connectionType && n.ConnectionID == id {
			return n.Note
		}
	}
	t.Fatalf("note for %s/%d missing from bundle", connectionType, id)
	return ""
}

func cloneBundle(b model.DataBundle) model.DataBundle {
	c := b
	c.Groups = append([]model.TransferGroup(nil), b.Groups...)
	c.KeyPairs = append([]model.TransferKeyPair(nil), b.KeyPairs...)
	c.SSHConnections = append([]model.TransferSSHConnection(nil), b.SSHConnections...)
	c.DBConnections = append([]model.TransferDBConnection(nil), b.DBConnections...)
	c.Projects = append([]model.TransferProject(nil), b.Projects...)
	c.Reports = append([]model.TransferReport(nil), b.Reports...)
	c.ConnectionNotes = append([]model.TransferConnectionNote(nil), b.ConnectionNotes...)
	return c
}

func countManagedRecords(t *testing.T, s *Store) int {
	t.Helper()
	total := 0
	for _, table := range managedTransferTables {
		var n int
		if err := s.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM "+table).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		total += n
	}
	return total
}

// noteRow is one stored connection_notes row, used to compare the full note
// table before and after a migration without assuming which rows survive.
type noteRow struct {
	connectionType string
	connectionID   int64
	note           string
}

// dumpConnectionNotes reads every connection_notes row in a stable order so a
// test can assert exact round-trip fidelity, including empty notes and rows
// whose reference or type is unrecognized.
func dumpConnectionNotes(t *testing.T, s *Store) []noteRow {
	t.Helper()
	rows, err := s.db.QueryContext(context.Background(),
		"SELECT connection_type, connection_id, note FROM connection_notes ORDER BY connection_type, connection_id")
	if err != nil {
		t.Fatalf("query connection_notes: %v", err)
	}
	defer rows.Close()
	out := make([]noteRow, 0)
	for rows.Next() {
		var r noteRow
		if err := rows.Scan(&r.connectionType, &r.connectionID, &r.note); err != nil {
			t.Fatalf("scan connection_notes: %v", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate connection_notes: %v", err)
	}
	return out
}

func TestExportDataIncludesEveryManagedRecordAndSecret(t *testing.T) {
	ctx := context.Background()
	src := newStoreWithKey(t, transferSourceKey)
	fx := seedTransferSource(t, src)

	bundle, err := src.ExportData(ctx)
	if err != nil {
		t.Fatalf("ExportData: %v", err)
	}
	if bundle.Format != model.DataBundleFormat {
		t.Errorf("format = %q, want %q", bundle.Format, model.DataBundleFormat)
	}
	if bundle.Version != model.DataBundleVersion {
		t.Errorf("version = %d, want %d", bundle.Version, model.DataBundleVersion)
	}
	if bundle.ExportedAt.IsZero() {
		t.Error("exported_at is zero")
	}
	if len(bundle.Groups) != 2 || len(bundle.KeyPairs) != 2 || len(bundle.SSHConnections) != 3 ||
		len(bundle.DBConnections) != 2 || len(bundle.Projects) != 1 || len(bundle.Reports) != 1 {
		t.Fatalf("bundle counts = %d/%d/%d/%d/%d/%d, want 2/2/3/2/1/1",
			len(bundle.Groups), len(bundle.KeyPairs), len(bundle.SSHConnections),
			len(bundle.DBConnections), len(bundle.Projects), len(bundle.Reports))
	}
	if len(bundle.ConnectionNotes) != 4 {
		t.Fatalf("bundle notes = %d, want 4 recognized notes", len(bundle.ConnectionNotes))
	}

	main := bundleSSH(t, bundle, fx.sshMain.ID)
	if main.Password != "ssh-secret" || main.ProxyPassword != "proxy-secret" {
		t.Errorf("ssh secrets = %q/%q, want ssh-secret/proxy-secret", main.Password, main.ProxyPassword)
	}
	if got := bundleNote(t, bundle, "ssh", fx.sshMain.ID); got != "primary ssh" {
		t.Errorf("ssh note = %q, want primary ssh", got)
	}
	if main.ProxyHost != "proxy.invalid" || main.ProxyPort != 1080 || main.ProxyUsername != "proxyuser" {
		t.Errorf("ssh proxy = %q/%d/%q", main.ProxyHost, main.ProxyPort, main.ProxyUsername)
	}
	if main.DefaultDir != "/srv/app" || main.GroupID != fx.groupA.ID {
		t.Errorf("ssh defaults = %q/%d", main.DefaultDir, main.GroupID)
	}
	if !main.CreatedAt.Equal(fx.sshMain.CreatedAt) || !main.UpdatedAt.Equal(fx.sshMain.UpdatedAt) {
		t.Errorf("ssh timestamps = %v/%v, want %v/%v", main.CreatedAt, main.UpdatedAt, fx.sshMain.CreatedAt, fx.sshMain.UpdatedAt)
	}

	keyed := bundleSSH(t, bundle, fx.sshKeyed.ID)
	if keyed.KeyPairID != fx.keyPair.ID {
		t.Errorf("keyed.key_pair_id = %d, want %d", keyed.KeyPairID, fx.keyPair.ID)
	}
	if keyed.JumpConnectionIDs != fmt.Sprintf("[%d]", fx.sshMain.ID) {
		t.Errorf("keyed.jump ids = %q", keyed.JumpConnectionIDs)
	}

	dbMain := bundleDB(t, bundle, fx.dbMain.ID)
	if dbMain.Password != "db-secret" {
		t.Errorf("db secret = %q", dbMain.Password)
	}
	if got := bundleNote(t, bundle, "db", fx.dbMain.ID); got != "primary db" {
		t.Errorf("db note = %q, want primary db", got)
	}
	if dbMain.SSHConnectionID != fx.sshMain.ID || dbMain.GroupID != fx.groupB.ID {
		t.Errorf("db refs = %d/%d", dbMain.SSHConnectionID, dbMain.GroupID)
	}
	if len(dbMain.Databases) != 2 || dbMain.Databases[0].Name != "app" || !dbMain.Databases[0].IsDefault {
		t.Errorf("db databases = %#v", dbMain.Databases)
	}

	kp := bundleKeyPair(t, bundle, fx.keyPair.ID)
	if kp.PublicKey != "public-key-material" || kp.PrivateKey != "private-key-material" ||
		kp.PrivateKeyPassphrase != "passphrase-material" {
		t.Errorf("key pair secrets = %q/%q/%q", kp.PublicKey, kp.PrivateKey, kp.PrivateKeyPassphrase)
	}

	if len(bundle.Reports) != 1 || bundle.Reports[0].ProjectID != fx.project.ID {
		t.Errorf("report project linkage = %#v, want project %d", bundle.Reports, fx.project.ID)
	}
}

func TestImportDataRoundTripsAcrossMasterKeys(t *testing.T) {
	ctx := context.Background()
	src := newStoreWithKey(t, transferSourceKey)
	fx := seedTransferSource(t, src)
	bundle, err := src.ExportData(ctx)
	if err != nil {
		t.Fatalf("ExportData: %v", err)
	}

	if src.codec.Key == transferDestKey {
		t.Fatal("source and destination master keys must differ for this test")
	}
	dst := newStoreWithKey(t, transferDestKey)
	if err := dst.ImportData(ctx, bundle); err != nil {
		t.Fatalf("ImportData: %v", err)
	}

	// Secrets must decrypt under the destination key.
	main, err := dst.GetSSH(ctx, fx.sshMain.ID)
	if err != nil {
		t.Fatalf("dest GetSSH main: %v", err)
	}
	if string(main.Password) != "ssh-secret" || string(main.ProxyPassword) != "proxy-secret" {
		t.Errorf("dest ssh secrets = %q/%q", main.Password, main.ProxyPassword)
	}
	if main.Note != "primary ssh" || main.DefaultDir != "/srv/app" {
		t.Errorf("dest ssh metadata = %q/%q", main.Note, main.DefaultDir)
	}
	if !main.CreatedAt.Equal(fx.sshMain.CreatedAt) || !main.UpdatedAt.Equal(fx.sshMain.UpdatedAt) {
		t.Errorf("dest ssh timestamps = %v/%v, want %v/%v", main.CreatedAt, main.UpdatedAt, fx.sshMain.CreatedAt, fx.sshMain.UpdatedAt)
	}
	if main.GroupID != fx.groupA.ID {
		t.Errorf("dest ssh group = %d, want %d", main.GroupID, fx.groupA.ID)
	}

	keyed, err := dst.GetSSH(ctx, fx.sshKeyed.ID)
	if err != nil {
		t.Fatalf("dest GetSSH keyed: %v", err)
	}
	if keyed.KeyPairID != fx.keyPair.ID {
		t.Errorf("dest keyed.key_pair_id = %d, want %d", keyed.KeyPairID, fx.keyPair.ID)
	}

	dbMain, err := dst.GetDB(ctx, fx.dbMain.ID)
	if err != nil {
		t.Fatalf("dest GetDB main: %v", err)
	}
	if string(dbMain.Password) != "db-secret" || dbMain.Note != "primary db" {
		t.Errorf("dest db secret/note = %q/%q", dbMain.Password, dbMain.Note)
	}
	if dbMain.SSHConnectionID != fx.sshMain.ID || dbMain.GroupID != fx.groupB.ID {
		t.Errorf("dest db refs = %d/%d", dbMain.SSHConnectionID, dbMain.GroupID)
	}
	if len(dbMain.Databases) != 2 || dbMain.Databases[0].Name != "app" || !dbMain.Databases[0].IsDefault {
		t.Errorf("dest db databases = %#v", dbMain.Databases)
	}

	kp, err := dst.GetKeyPair(ctx, fx.keyPair.ID)
	if err != nil {
		t.Fatalf("dest GetKeyPair: %v", err)
	}
	if string(kp.PublicKey) != "public-key-material" || string(kp.PrivateKey) != "private-key-material" ||
		string(kp.PrivateKeyPassphrase) != "passphrase-material" {
		t.Errorf("dest key pair secrets = %q/%q/%q", kp.PublicKey, kp.PrivateKey, kp.PrivateKeyPassphrase)
	}
	plain, err := dst.GetKeyPair(ctx, fx.plainKeyPair.ID)
	if err != nil {
		t.Fatalf("dest GetKeyPair plain: %v", err)
	}
	if string(plain.PrivateKey) != "only-private-material" || plain.PublicKey != nil {
		t.Errorf("dest plain key pair = %q/%q", plain.PublicKey, plain.PrivateKey)
	}

	// Dangling soft references must survive byte-for-byte.
	dangling, err := dst.GetSSH(ctx, fx.sshDangling.ID)
	if err != nil {
		t.Fatalf("dest GetSSH dangling: %v", err)
	}
	if dangling.KeyPairID != 999 || dangling.GroupID != 999 || dangling.JumpConnectionIDs != "[999]" {
		t.Errorf("dest dangling refs = %d/%d/%q", dangling.KeyPairID, dangling.GroupID, dangling.JumpConnectionIDs)
	}
	dbDangling, err := dst.GetDB(ctx, fx.dbDanglingTunnel.ID)
	if err != nil {
		t.Fatalf("dest GetDB dangling: %v", err)
	}
	if dbDangling.SSHConnectionID != 999 {
		t.Errorf("dest dangling tunnel = %d, want 999", dbDangling.SSHConnectionID)
	}

	// Hard report -> project linkage must survive and resolve.
	reports, err := dst.ListReports(ctx, "alpha")
	if err != nil {
		t.Fatalf("dest ListReports: %v", err)
	}
	if len(reports) != 1 || reports[0].ID != fx.report.ID || reports[0].Title != "Shipped 1.0" {
		t.Errorf("dest reports = %#v", reports)
	}
	if !reports[0].CreatedAt.Equal(fx.report.CreatedAt) {
		t.Errorf("dest report created_at = %v, want %v", reports[0].CreatedAt, fx.report.CreatedAt)
	}

	// The imported ids must not poison AUTOINCREMENT: new rows after a
	// migration still receive fresh ids above every imported one.
	newGroup, err := dst.CreateGroup(ctx, model.Group{Name: "post-import"})
	if err != nil {
		t.Fatalf("dest CreateGroup after import: %v", err)
	}
	if newGroup.ID <= fx.groupB.ID {
		t.Errorf("post-import group id = %d, want > imported max %d", newGroup.ID, fx.groupB.ID)
	}
}

func TestImportDataRejectsNonEmptyDestination(t *testing.T) {
	ctx := context.Background()
	src := newStoreWithKey(t, transferSourceKey)
	seedTransferSource(t, src)
	bundle, err := src.ExportData(ctx)
	if err != nil {
		t.Fatalf("ExportData: %v", err)
	}

	t.Run("managed record", func(t *testing.T) {
		dst := newStoreWithKey(t, transferDestKey)
		if _, err := dst.CreateGroup(ctx, model.Group{Name: "existing"}); err != nil {
			t.Fatalf("seed destination: %v", err)
		}
		err := dst.ImportData(ctx, bundle)
		if !errors.Is(err, ErrDestinationNotEmpty) {
			t.Fatalf("ImportData error = %v, want ErrDestinationNotEmpty", err)
		}
		if got := countManagedRecords(t, dst); got != 1 {
			t.Errorf("managed records after rejected import = %d, want 1", got)
		}
	})

	t.Run("connection note only", func(t *testing.T) {
		dst := newStoreWithKey(t, transferDestKey)
		if _, err := dst.db.ExecContext(ctx,
			"INSERT INTO connection_notes (connection_type, connection_id, note) VALUES ('ssh', 1, 'orphan note')"); err != nil {
			t.Fatalf("seed destination note: %v", err)
		}
		err := dst.ImportData(ctx, bundle)
		if !errors.Is(err, ErrDestinationNotEmpty) {
			t.Fatalf("ImportData error = %v, want ErrDestinationNotEmpty", err)
		}
	})

	t.Run("audit history does not block migration", func(t *testing.T) {
		dst := newStoreWithKey(t, transferDestKey)
		if err := dst.AppendAudit(ctx, model.AuditEvent{
			Operation: "seed", ResourceType: "test", ResourceID: "1", Source: "test", Result: "success",
		}); err != nil {
			t.Fatalf("seed destination audit: %v", err)
		}
		if err := dst.ImportData(ctx, bundle); err != nil {
			t.Fatalf("ImportData into audit-only destination: %v", err)
		}
		if got := countManagedRecords(t, dst); got == 0 {
			t.Error("managed records were not imported into audit-only destination")
		}
		var audits int
		if err := dst.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_events").Scan(&audits); err != nil {
			t.Fatalf("count audit events: %v", err)
		}
		if audits != 1 {
			t.Errorf("audit events = %d, want 1", audits)
		}
	})
}

func TestImportDataRejectsInvalidBundles(t *testing.T) {
	ctx := context.Background()
	src := newStoreWithKey(t, transferSourceKey)
	seedTransferSource(t, src)
	exported, err := src.ExportData(ctx)
	if err != nil {
		t.Fatalf("ExportData: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*model.DataBundle)
	}{
		{"unsupported format", func(b *model.DataBundle) { b.Format = "other" }},
		{"unsupported version", func(b *model.DataBundle) { b.Version = 99 }},
		{"missing exported_at", func(b *model.DataBundle) { b.ExportedAt = time.Time{} }},
		{"missing groups array", func(b *model.DataBundle) { b.Groups = nil }},
		{"missing key_pairs array", func(b *model.DataBundle) { b.KeyPairs = nil }},
		{"missing ssh_connections array", func(b *model.DataBundle) { b.SSHConnections = nil }},
		{"missing db_connections array", func(b *model.DataBundle) { b.DBConnections = nil }},
		{"missing projects array", func(b *model.DataBundle) { b.Projects = nil }},
		{"missing reports array", func(b *model.DataBundle) { b.Reports = nil }},
		{"missing connection_notes array", func(b *model.DataBundle) { b.ConnectionNotes = nil }},
		{"duplicate group id", func(b *model.DataBundle) {
			b.Groups = append(b.Groups, b.Groups[0])
		}},
		{"duplicate group name", func(b *model.DataBundle) {
			dup := b.Groups[0]
			dup.ID = 5000
			b.Groups = append(b.Groups, dup)
		}},
		{"duplicate ssh name", func(b *model.DataBundle) {
			dup := b.SSHConnections[0]
			dup.ID = 5000
			b.SSHConnections = append(b.SSHConnections, dup)
		}},
		{"invalid ssh name", func(b *model.DataBundle) { b.SSHConnections[0].Name = "bad name!" }},
		{"malformed jump json", func(b *model.DataBundle) { b.SSHConnections[0].JumpConnectionIDs = "not-json" }},
		{"negative group id", func(b *model.DataBundle) { b.SSHConnections[0].GroupID = -1 }},
		{"missing ssh timestamp", func(b *model.DataBundle) { b.SSHConnections[0].CreatedAt = time.Time{} }},
		{"report references missing project", func(b *model.DataBundle) { b.Reports[0].ProjectID = 424242 }},
		{"invalid report fields", func(b *model.DataBundle) { b.Reports[0].Title = "" }},
		{"duplicate key pair id", func(b *model.DataBundle) {
			b.KeyPairs = append(b.KeyPairs, b.KeyPairs[0])
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bundle := cloneBundle(exported)
			tc.mutate(&bundle)
			dst := newStoreWithKey(t, transferDestKey)
			err := dst.ImportData(ctx, bundle)
			if !errors.Is(err, ErrValidation) {
				t.Fatalf("ImportData error = %v, want ErrValidation", err)
			}
			if got := countManagedRecords(t, dst); got != 0 {
				t.Errorf("managed records after rejected import = %d, want 0", got)
			}
		})
	}
}

func TestImportDataRejectsSSHPasswordAndKeyPairTogether(t *testing.T) {
	ctx := context.Background()
	src := newStoreWithKey(t, transferSourceKey)
	fx := seedTransferSource(t, src)
	bundle, err := src.ExportData(ctx)
	if err != nil {
		t.Fatalf("ExportData: %v", err)
	}

	// Give the password-only profile a stored key-pair selection too. The
	// normal write path refuses this pair because password and key_pair_id are
	// mutually exclusive, so import must reject it rather than create a row the
	// live API would never accept.
	patched := false
	for i := range bundle.SSHConnections {
		if bundle.SSHConnections[i].ID == fx.sshMain.ID {
			bundle.SSHConnections[i].KeyPairID = fx.keyPair.ID
			patched = true
		}
	}
	if !patched {
		t.Fatal("test setup did not patch the password profile")
	}

	dst := newStoreWithKey(t, transferDestKey)
	if err := dst.ImportData(ctx, bundle); !errors.Is(err, ErrValidation) {
		t.Fatalf("ImportData error = %v, want ErrValidation", err)
	}
	if got := countManagedRecords(t, dst); got != 0 {
		t.Errorf("managed records after rejected import = %d, want 0", got)
	}
}

func TestImportDataPreservesEveryConnectionNoteRow(t *testing.T) {
	ctx := context.Background()
	src := newStoreWithKey(t, transferSourceKey)
	seedTransferSource(t, src)

	// Notes the write path cannot create: an empty note, notes with no
	// matching connection, and a note under an unrecognized connection type.
	before := len(dumpConnectionNotes(t, src))
	extraNotes := []noteRow{
		{connectionType: "ssh", connectionID: 424242, note: "orphan ssh note"},
		{connectionType: "ssh", connectionID: 424243, note: ""},
		{connectionType: "legacy", connectionID: 7, note: "unrecognized type note"},
		{connectionType: "db", connectionID: 424244, note: "orphan db note"},
	}
	for _, n := range extraNotes {
		if _, err := src.db.ExecContext(ctx,
			"INSERT INTO connection_notes (connection_type, connection_id, note) VALUES (?, ?, ?)",
			n.connectionType, n.connectionID, n.note); err != nil {
			t.Fatalf("seed extra note %#v: %v", n, err)
		}
	}

	// The full source note table is the expected post-migration state: the
	// seeded recognized notes plus every extra row above.
	want := dumpConnectionNotes(t, src)
	if len(want) != before+len(extraNotes) {
		t.Fatalf("source notes = %d, want %d", len(want), before+len(extraNotes))
	}

	bundle, err := src.ExportData(ctx)
	if err != nil {
		t.Fatalf("ExportData: %v", err)
	}

	dst := newStoreWithKey(t, transferDestKey)
	if err := dst.ImportData(ctx, bundle); err != nil {
		t.Fatalf("ImportData: %v", err)
	}

	got := dumpConnectionNotes(t, dst)
	if len(got) != len(want) {
		t.Fatalf("imported notes = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("imported note[%d] = %#v, want %#v", i, got[i], want[i])
		}
	}
}

func TestImportDataRejectsDuplicateConnectionNotes(t *testing.T) {
	ctx := context.Background()
	src := newStoreWithKey(t, transferSourceKey)
	seedTransferSource(t, src)
	bundle, err := src.ExportData(ctx)
	if err != nil {
		t.Fatalf("ExportData: %v", err)
	}
	sshID := bundle.SSHConnections[0].ID
	// Two rows sharing the table's UNIQUE (connection_type, connection_id)
	// key are unrecoverable, so import must reject the bundle up front rather
	// than fail partway through the write transaction.
	bundle.ConnectionNotes = []model.TransferConnectionNote{
		{ConnectionType: "ssh", ConnectionID: sshID, Note: "first"},
		{ConnectionType: "ssh", ConnectionID: sshID, Note: "second"},
	}

	dst := newStoreWithKey(t, transferDestKey)
	if err := dst.ImportData(ctx, bundle); !errors.Is(err, ErrValidation) {
		t.Fatalf("ImportData error = %v, want ErrValidation", err)
	}
	if got := countManagedRecords(t, dst); got != 0 {
		t.Errorf("managed records after rejected import = %d, want 0", got)
	}
}

func TestImportDataRollsBackOnMidImportFailure(t *testing.T) {
	ctx := context.Background()
	src := newStoreWithKey(t, transferSourceKey)
	seedTransferSource(t, src)
	bundle, err := src.ExportData(ctx)
	if err != nil {
		t.Fatalf("ExportData: %v", err)
	}

	dst := newStoreWithKey(t, transferDestKey)
	// Force the report insert (which runs after groups, key pairs, and both
	// connection tables) to fail so rollback of earlier inserts is observable.
	if _, err := dst.db.ExecContext(ctx,
		`CREATE TRIGGER fail_reports BEFORE INSERT ON reports BEGIN SELECT RAISE(ABORT, 'forced failure'); END`); err != nil {
		t.Fatalf("create failure trigger: %v", err)
	}

	if err := dst.ImportData(ctx, bundle); err == nil {
		t.Fatal("ImportData succeeded despite forced report failure")
	}
	if got := countManagedRecords(t, dst); got != 0 {
		t.Errorf("managed records after rolled-back import = %d, want 0", got)
	}
}
