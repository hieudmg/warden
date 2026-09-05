package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/lithammer/fuzzysearch/fuzzy"

	"warden/internal/client/agent"
	"warden/internal/client/api"
	clientdb "warden/internal/client/db"
	"warden/internal/client/picker"
	clientreport "warden/internal/client/report"
	clientssh "warden/internal/client/ssh"
	"warden/internal/client/terminal"
	"warden/internal/config"
	"warden/internal/model"
)

var (
	runAgentSSH   = agent.RunSSH
	runAgentCopy  = agent.RunCopy
	runAgentDB    = agent.RunTunneledDB
	runAgentServe = agent.Serve
	runDirectDB   = clientdb.RunQuery
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, os.LookupEnv))
}

func run(args []string, stdout, stderr io.Writer, lookupEnv func(string) (string, bool)) int {
	if len(args) == 0 || isHelp(args[0]) {
		printUsage(stdout)
		return 0
	}

	root := flag.NewFlagSet("warden", flag.ContinueOnError)
	root.SetOutput(stderr)
	root.Usage = func() {}

	configPath := root.String("config", "", "path to client config JSON")
	if err := root.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printUsage(stdout)
			return 0
		}
		return 2
	}

	rest := root.Args()
	if len(rest) == 0 || isHelp(rest[0]) {
		printUsage(stdout)
		return 0
	}

	configPathSet := flagWasSet(root, "config")

	switch rest[0] {
	case "agent":
		return runAgent(rest[1:], stderr)
	case "ssh":
		return runSSH(rest[1:], *configPath, configPathSet, stdout, stderr, lookupEnv)
	case "db":
		return runDB(rest[1:], *configPath, configPathSet, stdout, stderr, lookupEnv)
	case "xssh":
		return runXSSH(rest[1:], *configPath, configPathSet, stdout, stderr, lookupEnv)
	case "report":
		return runReport(rest[1:], *configPath, configPathSet, stdout, stderr, lookupEnv)
	case "config":
		return runConfig(rest[1:], *configPath, configPathSet, stdout, stderr, lookupEnv)
	case "cp":
		return runCP(rest[1:], *configPath, configPathSet, stdout, stderr, lookupEnv)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", rest[0])
		printUsage(stderr)
		return 2
	}
}

func runSSH(args []string, configPath string, configPathSet bool, stdout, stderr io.Writer, lookupEnv func(string) (string, bool)) int {
	if len(args) == 1 && isFlagHelp(args[0]) {
		printSSHUsage(stdout)
		return 0
	}
	if len(args) != 2 {
		fmt.Fprintln(stderr, "usage: warden ssh <connection> <command>")
		return 2
	}

	cfg, err := loadClient(configPath, configPathSet, lookupEnv)
	if err != nil {
		fmt.Fprintf(stderr, "invalid client config: %v\n", err)
		return 1
	}

	cl := api.New(cfg.APIBaseURL, &http.Client{Timeout: cfg.Timeout})
	ctx := context.Background()

	conns, err := cl.ListSSH(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "ssh: %v\n", err)
		return 1
	}

	id := int64(-1)
	for _, c := range conns {
		if c.Name == args[0] {
			id = c.ID
			break
		}
	}
	if id < 0 {
		fmt.Fprintf(stderr, "ssh: connection %q not found\n", args[0])
		return 1
	}

	bundle, err := cl.GetSSHBundle(ctx, id)
	if err != nil {
		fmt.Fprintf(stderr, "ssh: %v\n", err)
		return 1
	}

	err = runAgentSSH(ctx, bundle, args[1], clientssh.Streams{Stdin: os.Stdin, Stdout: stdout, Stderr: stderr})
	if err == nil {
		return 0
	}
	var exitErr *clientssh.ExitStatusError
	if errors.As(err, &exitErr) {
		return exitErr.Status
	}
	fmt.Fprintf(stderr, "ssh: %v\n", err)
	return 1
}

func parseDBReference(raw string) (profileName, databaseName string, err error) {
	if raw == "" {
		return "", "", errors.New("database connection reference must not be empty")
	}
	if strings.Count(raw, "/") > 1 {
		return "", "", fmt.Errorf("database connection reference %q contains more than one separator", raw)
	}
	profileName, databaseName, _ = strings.Cut(raw, "/")
	if profileName == "" {
		return "", "", errors.New("database connection profile name must not be empty")
	}
	if strings.Contains(raw, "/") && databaseName == "" {
		return "", "", errors.New("database selector must not be empty")
	}
	return profileName, databaseName, nil
}

func runDB(args []string, configPath string, configPathSet bool, stdout, stderr io.Writer, lookupEnv func(string) (string, bool)) int {
	if len(args) == 1 && isFlagHelp(args[0]) {
		printDBUsage(stdout)
		return 0
	}
	if len(args) != 2 {
		fmt.Fprintln(stderr, "usage: warden db <connection> <sql>")
		return 2
	}
	profileName, databaseName, err := parseDBReference(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "db: %v\n", err)
		return 2
	}

	cfg, err := loadClient(configPath, configPathSet, lookupEnv)
	if err != nil {
		fmt.Fprintf(stderr, "invalid client config: %v\n", err)
		return 1
	}

	cl := api.New(cfg.APIBaseURL, &http.Client{Timeout: cfg.Timeout})
	// context.Background() is deliberate and mirrors runSSH: both CLI
	// commands are one-shot processes, the default SIGINT behavior
	// terminates them, and API calls are bounded by cfg.Timeout. A hung
	// DB query is not bounded by ctx (the driver would abort on cancel);
	// cancellation of long queries is a known limitation shared with
	// warden ssh.
	ctx := context.Background()

	conns, err := cl.ListDB(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "db: %v\n", err)
		return 1
	}

	id := int64(-1)
	for _, c := range conns {
		if c.Name == profileName {
			id = c.ID
			break
		}
	}
	if id < 0 {
		fmt.Fprintf(stderr, "db: connection %q not found\n", profileName)
		return 1
	}

	bundle, err := cl.GetDBBundle(ctx, id, databaseName)
	if err != nil {
		fmt.Fprintf(stderr, "db: %v\n", err)
		return 1
	}

	var runErr error
	if bundle.SSH != nil {
		runErr = runAgentDB(ctx, bundle, args[1], stdout)
	} else {
		runErr = runDirectDB(ctx, bundle, args[1], stdout)
	}
	if runErr != nil {
		fmt.Fprintf(stderr, "db: %v\n", runErr)
		return 1
	}
	return 0
}

func runXSSH(args []string, configPath string, configPathSet bool, stdout, stderr io.Writer, lookupEnv func(string) (string, bool)) int {
	fs := flag.NewFlagSet("xssh", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {}
	acceptNew := fs.Bool("accept-new", false, "accept unknown host keys after interactive confirmation")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printXSSHUsage(stdout)
			return 0
		}
		return 2
	}
	if fs.NArg() > 1 {
		fmt.Fprintln(stderr, "usage: warden xssh [--accept-new] [connection]")
		return 2
	}
	name := ""
	if fs.NArg() == 1 {
		name = fs.Arg(0)
	}

	cfg, err := loadClient(configPath, configPathSet, lookupEnv)
	if err != nil {
		fmt.Fprintf(stderr, "invalid client config: %v\n", err)
		return 1
	}

	cl := api.New(cfg.APIBaseURL, &http.Client{Timeout: cfg.Timeout})
	ctx := context.Background()

	conns, err := cl.ListSSH(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "xssh: %v\n", err)
		return 1
	}

	var sel model.SSHConnection
	if name != "" {
		found := false
		for _, c := range conns {
			if c.Name == name {
				sel = c
				found = true
				break
			}
		}
		if !found {
			fmt.Fprintf(stderr, "xssh: connection %q not found\n", name)
			return 1
		}
	} else {
		// The picker owns its terminal session: Select enters raw mode,
		// renders, and restores the terminal before returning, so no
		// picker goroutine remains to consume input meant for the SSH
		// session. A fresh terminal session is created below for the
		// interactive SSH session.
		pickerSession, err := terminal.NewSession()
		if err != nil {
			fmt.Fprintf(stderr, "xssh: %v\n", err)
			return 1
		}
		sel, err = picker.Select(pickerSession, conns)
		if err != nil {
			fmt.Fprintf(stderr, "xssh: %v\n", err)
			return 1
		}
	}

	clientssh.WriteProgress(stderr, "Fetching credentials...")
	bundle, err := cl.GetSSHBundle(ctx, sel.ID)
	if err != nil {
		fmt.Fprintf(stderr, "xssh: %v\n", err)
		return 1
	}

	term, err := terminal.NewSession()
	if err != nil {
		fmt.Fprintf(stderr, "xssh: %v\n", err)
		return 1
	}

	if err := clientssh.RunInteractive(ctx, bundle, term, *acceptNew); err != nil {
		var exitErr *clientssh.ExitStatusError
		if errors.As(err, &exitErr) {
			return exitErr.Status
		}
		fmt.Fprintf(stderr, "xssh: %v\n", err)
		return 1
	}
	return 0
}

func runReport(args []string, configPath string, configPathSet bool, stdout, stderr io.Writer, lookupEnv func(string) (string, bool)) int {
	if len(args) == 0 || isHelp(args[0]) {
		printReportUsage(stdout)
		return 0
	}
	if args[0] != "create" {
		fmt.Fprintf(stderr, "unknown report command %q\n\n", args[0])
		printReportUsage(stderr)
		return 2
	}

	return runReportCreate(args[1:], configPath, configPathSet, stdout, stderr, lookupEnv)
}

func runReportCreate(args []string, configPath string, configPathSet bool, stdout, stderr io.Writer, lookupEnv func(string) (string, bool)) int {
	if len(args) == 0 || isHelp(args[0]) {
		printReportCreateUsage(stdout)
		return 0
	}

	project := args[0]
	fs := flag.NewFlagSet("report create", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {}

	title := fs.String("title", "", "report title")
	summary := fs.String("summary", "", "report summary")
	agentModel := fs.String("agent-model", "", "agent model name")
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printReportCreateUsage(stdout)
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "report create does not accept extra positional arguments")
		printReportCreateUsage(stderr)
		return 2
	}
	if project == "" || *title == "" || *summary == "" || *agentModel == "" {
		fmt.Fprintln(stderr, "report create requires <project>, --title, --summary, and --agent-model")
		printReportCreateUsage(stderr)
		return 2
	}

	cfg, err := loadClient(configPath, configPathSet, lookupEnv)
	if err != nil {
		fmt.Fprintf(stderr, "invalid client config: %v\n", err)
		return 1
	}

	cl := api.New(cfg.APIBaseURL, &http.Client{Timeout: cfg.Timeout})
	reportClient := clientreport.New(cl)
	ctx := context.Background()

	r, err := reportClient.CreateReport(ctx, model.ReportRequest{
		Project:    project,
		Title:      *title,
		Summary:    *summary,
		AgentModel: *agentModel,
	})
	if err != nil {
		fmt.Fprintf(stderr, "report create: %v\n", err)
		return 1
	}

	// One-line confirmation only: report id and server timestamp, never the
	// body (title/summary). The body is intentionally not echoed.
	fmt.Fprintf(stdout, "report %d created for %s at %s\n", r.ID, r.Project, r.CreatedAt.UTC().Format(time.RFC3339))
	return 0
}

func runConfig(args []string, configPath string, configPathSet bool, stdout, stderr io.Writer, lookupEnv func(string) (string, bool)) int {
	if len(args) == 0 || isHelp(args[0]) {
		printConfigUsage(stdout)
		return 0
	}
	if args[0] != "search" {
		fmt.Fprintf(stderr, "unknown config command %q\n\n", args[0])
		printConfigUsage(stderr)
		return 2
	}
	if len(args) == 2 && isFlagHelp(args[1]) {
		printConfigSearchUsage(stdout)
		return 0
	}
	if len(args) != 2 || strings.TrimSpace(args[1]) == "" {
		fmt.Fprintln(stderr, "usage: warden config search <query>")
		return 2
	}

	cfg, err := loadClient(configPath, configPathSet, lookupEnv)
	if err != nil {
		fmt.Fprintf(stderr, "invalid client config: %v\n", err)
		return 1
	}

	cl := api.New(cfg.APIBaseURL, &http.Client{Timeout: cfg.Timeout})
	ctx := context.Background()
	sshConns, err := cl.ListSSH(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "config search: %v\n", err)
		return 1
	}
	dbConns, err := cl.ListDB(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "config search: %v\n", err)
		return 1
	}

	writeConfigSearchResults(stdout, args[1], sshConns, dbConns)
	return 0
}

type configSearchScore struct {
	matched        int
	normalizedTypo float64
	exact          int
	prefix         int
	originalIndex  int
}

func writeConfigSearchResults(w io.Writer, query string, sshConns []model.SSHConnection, dbConns []model.DBConnection) {
	sshNames := make(map[int64]string, len(sshConns))
	type matchedSSH struct {
		connection model.SSHConnection
		score      configSearchScore
	}
	var sshMatches []matchedSSH
	for index, conn := range sshConns {
		sshNames[conn.ID] = conn.Name
		if score, ok := scoreConfigSearch(query, conn.Name, conn.Host); ok {
			score.originalIndex = index
			sshMatches = append(sshMatches, matchedSSH{connection: conn, score: score})
		}
	}
	sort.SliceStable(sshMatches, func(i, j int) bool {
		return lessConfigSearchScore(sshMatches[i].score, sshMatches[j].score)
	})

	type matchedDatabase struct {
		connection model.DBConnection
		name       string
		score      configSearchScore
	}
	var dbMatches []matchedDatabase
	index := 0
	for _, conn := range dbConns {
		for _, database := range conn.Databases {
			if score, ok := scoreConfigSearch(query, conn.Name, conn.Host, database.Name); ok {
				score.originalIndex = index
				dbMatches = append(dbMatches, matchedDatabase{connection: conn, name: database.Name, score: score})
			}
			index++
		}
	}
	sort.SliceStable(dbMatches, func(i, j int) bool {
		return lessConfigSearchScore(dbMatches[i].score, dbMatches[j].score)
	})

	if len(sshMatches) == 0 && len(dbMatches) == 0 {
		fmt.Fprintln(w, "No matching connections.")
		return
	}

	var lines []string
	if len(sshMatches) > 0 {
		lines = append(lines, "SSH")
		for i, match := range sshMatches {
			conn := match.connection
			entry := sanitizeConfigSearchField(conn.Name) + " — " + sanitizeConfigSearchField(conn.Host)
			lines = append(lines, treeEntry(i, len(sshMatches), entry))
		}
	}
	if len(dbMatches) > 0 {
		if len(lines) > 0 {
			lines = append(lines, "")
		}
		lines = append(lines, "DB")
		for i, match := range dbMatches {
			conn := match.connection
			database := sanitizeConfigSearchField(match.name)
			entry := sanitizeConfigSearchField(conn.Name) + "/" + database + " — " + sanitizeConfigSearchField(conn.Host) + "/" + database
			if conn.SSHConnectionID != 0 {
				sshName, ok := sshNames[conn.SSHConnectionID]
				if !ok {
					sshName = fmt.Sprintf("unavailable (id: %d)", conn.SSHConnectionID)
				}
				entry += " — SSH: " + sanitizeConfigSearchField(sshName)
			}
			lines = append(lines, treeEntry(i, len(dbMatches), entry))
		}
	}
	fmt.Fprintln(w, strings.Join(lines, "\n"))
}

func scoreConfigSearch(query string, fields ...string) (configSearchScore, bool) {
	queryWords := configSearchWords(query)
	if len(queryWords) == 0 {
		return configSearchScore{}, strings.TrimSpace(query) == ""
	}

	targetWords := make([]string, 0)
	for _, field := range fields {
		targetWords = append(targetWords, configSearchWords(field)...)
	}

	var score configSearchScore
	for _, queryWord := range queryWords {
		best, ok := bestConfigSearchWord(queryWord, targetWords)
		if !ok {
			continue
		}
		score.matched++
		score.normalizedTypo += best.normalizedTypo
		score.exact += best.exact
		score.prefix += best.prefix
	}
	return score, score.matched > 0
}

type configSearchWordScore struct {
	normalizedTypo float64
	exact          int
	prefix         int
}

func bestConfigSearchWord(queryWord string, targetWords []string) (configSearchWordScore, bool) {
	var best configSearchWordScore
	found := false
	for _, targetWord := range targetWords {
		candidate, ok := scoreConfigSearchWord(queryWord, targetWord)
		if !ok {
			continue
		}
		if !found || lessConfigSearchWordScore(candidate, best) {
			best, found = candidate, true
		}
	}
	return best, found
}

func scoreConfigSearchWord(queryWord, targetWord string) (configSearchWordScore, bool) {
	queryWord = strings.ToLower(queryWord)
	targetWord = strings.ToLower(targetWord)
	if queryWord == "" || targetWord == "" {
		return configSearchWordScore{}, false
	}

	candidate := targetWord
	prefix := false
	if len([]rune(targetWord)) > len([]rune(queryWord)) {
		prefixRunes := []rune(targetWord)[:len([]rune(queryWord))]
		prefixDistance := fuzzy.LevenshteinDistance(queryWord, string(prefixRunes))
		if prefixDistance < fuzzy.LevenshteinDistance(queryWord, targetWord) {
			candidate = string(prefixRunes)
			prefix = true
		}
	}

	distance := fuzzy.LevenshteinDistance(queryWord, candidate)
	if distance > configSearchMaxDistance(len([]rune(queryWord))) {
		return configSearchWordScore{}, false
	}
	maxLength := len([]rune(queryWord))
	if candidateLength := len([]rune(candidate)); candidateLength > maxLength {
		maxLength = candidateLength
	}
	score := configSearchWordScore{normalizedTypo: float64(distance) / float64(maxLength)}
	if distance == 0 && !prefix {
		score.exact = 1
	}
	if prefix {
		score.prefix = 1
	}
	return score, true
}

func lessConfigSearchWordScore(a, b configSearchWordScore) bool {
	if a.normalizedTypo != b.normalizedTypo {
		return a.normalizedTypo < b.normalizedTypo
	}
	if a.exact != b.exact {
		return a.exact > b.exact
	}
	return a.prefix > b.prefix
}

func lessConfigSearchScore(a, b configSearchScore) bool {
	if a.matched != b.matched {
		return a.matched > b.matched
	}
	if a.normalizedTypo != b.normalizedTypo {
		return a.normalizedTypo < b.normalizedTypo
	}
	if a.exact != b.exact {
		return a.exact > b.exact
	}
	if a.prefix != b.prefix {
		return a.prefix > b.prefix
	}
	return a.originalIndex < b.originalIndex
}

func configSearchWords(value string) []string {
	return strings.FieldsFunc(strings.ToLower(strings.TrimSpace(value)), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
}

func configSearchMaxDistance(queryLength int) int {
	if queryLength <= 1 {
		return 0
	}
	maxDistance := queryLength / 3
	if maxDistance < 1 {
		return 1
	}
	return maxDistance
}

func treeEntry(index, total int, value string) string {
	if index == total-1 {
		return "└── " + value
	}
	return "├── " + value
}

func sanitizeConfigSearchField(value string) string {
	var b strings.Builder
	for _, r := range value {
		switch r {
		case '\x1b':
			b.WriteString(`\x1b`)
		case '\r':
			b.WriteString(`\r`)
		case '\n':
			b.WriteString(`\n`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if unicode.IsControl(r) {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	return b.String()
}

// cpEndpoint is one parsed cp operand: a local path or a remote
// connection:path pair. connection is nil for local operands.
type cpEndpoint struct {
	path       string
	connection *model.SSHConnection
}

// cpUsageError marks a malformed endpoint operand (empty connection name
// or path). runCP reports these as usage errors with exit code 2.
type cpUsageError struct{ message string }

func (e cpUsageError) Error() string { return e.message }

// parseCPEndpoint splits a cp operand into a local path or a remote
// connection:path pair. Windows drive-letter volumes (C:\... or C:/...)
// are local paths on every host: filepath.VolumeName only recognizes them
// on Windows, so the drive-letter pattern is checked explicitly as well.
// Operands without a colon are local. For remote operands the connection
// name must match a configured profile exactly.
func parseCPEndpoint(raw string, connections []model.SSHConnection) (cpEndpoint, error) {
	if filepath.VolumeName(raw) != "" || isWindowsDrivePath(raw) {
		return cpEndpoint{path: raw}, nil
	}
	idx := strings.Index(raw, ":")
	if idx < 0 {
		return cpEndpoint{path: raw}, nil
	}
	name, path := raw[:idx], raw[idx+1:]
	if name == "" {
		return cpEndpoint{}, cpUsageError{message: fmt.Sprintf("empty connection name in %q", raw)}
	}
	if path == "" {
		return cpEndpoint{}, cpUsageError{message: fmt.Sprintf("empty path in %q", raw)}
	}
	for i := range connections {
		if connections[i].Name == name {
			return cpEndpoint{path: path, connection: &connections[i]}, nil
		}
	}
	return cpEndpoint{}, fmt.Errorf("connection %q not found", name)
}

// sameCPRemoteHost reports whether two remote cp operands refer to the same
// configured host and port. Host names are compared case-insensitively and
// without resolving them, so the preflight does not perform network work.
func sameCPRemoteHost(source, destination cpEndpoint) bool {
	if source.connection == nil || destination.connection == nil {
		return false
	}
	return source.connection.Port == destination.connection.Port &&
		strings.EqualFold(source.connection.Host, destination.connection.Host)
}

// isWindowsDrivePath reports whether raw starts with a Windows drive-letter
// volume such as C:\ or C:/.
func isWindowsDrivePath(raw string) bool {
	return len(raw) >= 3 && raw[1] == ':' &&
		(raw[0] >= 'A' && raw[0] <= 'Z' || raw[0] >= 'a' && raw[0] <= 'z') &&
		(raw[2] == '\\' || raw[2] == '/')
}

// isCPRemoteSyntax identifies an operand that requires profile lookup. A
// Windows drive path is local even on a non-Windows build, while any other
// colon remains the remote connection/path separator.
func isCPRemoteSyntax(raw string) bool {
	if filepath.VolumeName(raw) != "" || isWindowsDrivePath(raw) {
		return false
	}
	return strings.Contains(raw, ":")
}

func runCP(args []string, configPath string, configPathSet bool, stdout, stderr io.Writer, lookupEnv func(string) (string, bool)) int {
	if len(args) == 1 && isFlagHelp(args[0]) {
		printCPUsage(stdout)
		return 0
	}
	if len(args) != 2 {
		fmt.Fprintln(stderr, "usage: warden cp <source> <destination>")
		return 2
	}
	if !isCPRemoteSyntax(args[0]) && !isCPRemoteSyntax(args[1]) {
		fmt.Fprintln(stderr, "cp: local-to-local copies are not supported")
		return 2
	}

	cfg, err := loadClient(configPath, configPathSet, lookupEnv)
	if err != nil {
		fmt.Fprintf(stderr, "invalid client config: %v\n", err)
		return 1
	}

	cl := api.New(cfg.APIBaseURL, &http.Client{Timeout: cfg.Timeout})
	ctx := context.Background()

	conns, err := cl.ListSSH(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "cp: %v\n", err)
		return 1
	}

	source, err := parseCPEndpoint(args[0], conns)
	if err != nil {
		return reportCPParseError(stderr, err)
	}
	destination, err := parseCPEndpoint(args[1], conns)
	if err != nil {
		return reportCPParseError(stderr, err)
	}

	if sameCPRemoteHost(source, destination) {
		fmt.Fprintf(stderr, "cp: refusing to copy between remote endpoints on same host %q:%d\n", source.connection.Host, source.connection.Port)
		return 1
	}

	if source.connection == nil && destination.connection == nil {
		fmt.Fprintln(stderr, "cp: local-to-local copies are not supported")
		return 2
	}

	src, err := resolveAgentCPEndpoint(source, cl, ctx)
	if err != nil {
		fmt.Fprintf(stderr, "cp: %v\n", err)
		return 1
	}
	dst, err := resolveAgentCPEndpoint(destination, cl, ctx)
	if err != nil {
		fmt.Fprintf(stderr, "cp: %v\n", err)
		return 1
	}

	if err := runAgentCopy(ctx, agent.CopyRequest{Source: src, Destination: dst}); err != nil {
		fmt.Fprintf(stderr, "cp: %v\n", err)
		return 1
	}
	return 0
}

// reportCPParseError reports an endpoint parse failure. Malformed operands
// (empty connection name or path) are usage errors with exit 2; unknown
// connection names are lookup failures with exit 1.
func reportCPParseError(stderr io.Writer, err error) int {
	var usageErr cpUsageError
	if errors.As(err, &usageErr) {
		fmt.Fprintf(stderr, "cp: %v\n", err)
		return 2
	}
	fmt.Fprintf(stderr, "cp: %v\n", err)
	return 1
}

// resolveAgentCPEndpoint converts a parsed endpoint into the serializable
// request form consumed by the local agent. Remote endpoints fetch their
// complete transport bundle; local paths are made absolute because the
// detached agent may have a different working directory.
func resolveAgentCPEndpoint(ep cpEndpoint, cl *api.Client, ctx context.Context) (agent.CopyEndpoint, error) {
	if ep.connection == nil {
		absolute, err := filepath.Abs(ep.path)
		if err != nil {
			return agent.CopyEndpoint{}, err
		}
		return agent.CopyEndpoint{Path: absolute}, nil
	}
	bundle, err := cl.GetSSHBundle(ctx, ep.connection.ID)
	if err != nil {
		return agent.CopyEndpoint{}, err
	}
	return agent.CopyEndpoint{Path: ep.path, Bundle: &bundle}, nil
}

// runAgent serves the hidden lifecycle command used by the client-side agent
// startup path. It deliberately does not appear in printUsage.
func runAgent(args []string, stderr io.Writer) int {
	if len(args) != 1 || args[0] != "serve" {
		fmt.Fprintln(stderr, "usage: warden agent serve")
		return 2
	}

	runtime, err := agent.NewRuntime()
	if err != nil {
		fmt.Fprintf(stderr, "agent: %v\n", err)
		return 1
	}
	listener, err := runtime.Listen()
	if err != nil {
		fmt.Fprintf(stderr, "agent: %v\n", err)
		return 1
	}
	defer runtime.Cleanup()

	token, err := runtime.ReadToken()
	if err != nil {
		fmt.Fprintf(stderr, "agent: %v\n", err)
		return 1
	}
	pool := agent.NewDefaultPool(time.Now, 10*time.Minute)
	if err := runAgentServe(context.Background(), listener, token, pool); err != nil {
		fmt.Fprintf(stderr, "agent: %v\n", err)
		return 1
	}
	return 0
}

func printCPUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  warden cp <source> <destination>
`)
}

func loadClient(configPath string, configPathSet bool, lookupEnv func(string) (string, bool)) (config.Client, error) {
	return config.LoadClient(config.ClientOptions{
		ConfigPath:    configPath,
		ConfigPathSet: configPathSet,
		LookupEnv:     lookupEnv,
	})
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  warden [--config path] ssh <connection> <command>
  warden [--config path] db <connection> <sql>
  warden [--config path] xssh [connection]
  warden [--config path] report create <project> --title <title> --summary <summary> --agent-model <name>
  warden [--config path] config search <query>
  warden [--config path] cp <source> <destination>
  warden --help

Environment overrides:
  WARDEN_CLIENT_CONFIG
  WARDEN_CLIENT_API_BASE_URL
  WARDEN_CLIENT_TIMEOUT
`)
}

func printSSHUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  warden ssh <connection> <command>
`)
}

func printDBUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  warden db <connection> <sql>
`)
}

func printXSSHUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  warden xssh [connection]

Options:
  --accept-new  accept unknown host keys after interactive confirmation
`)
}

func printReportUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  warden report create <project> --title <title> --summary <summary> --agent-model <name>
`)
}

func printReportCreateUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  warden report create <project> --title <title> --summary <summary> --agent-model <name>
`)
}

func printConfigUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  warden config search <query>
`)
}

func printConfigSearchUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  warden config search <query>
`)
}

func isHelp(value string) bool {
	return isFlagHelp(value) || value == "help"
}

func isFlagHelp(value string) bool {
	return value == "-h" || value == "--help"
}

func flagWasSet(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}
