package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"warden/internal/config"
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

	fmt.Fprintf(stdout, "client bootstrap ready for ssh via %s\n", cfg.APIBaseURL)
	return 0
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

	cfg, err := loadClient(configPath, configPathSet, lookupEnv)
	if err != nil {
		fmt.Fprintf(stderr, "invalid client config: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "client bootstrap ready for db via %s\n", cfg.APIBaseURL)
	return 0
}

func runXSSH(args []string, configPath string, configPathSet bool, stdout, stderr io.Writer, lookupEnv func(string) (string, bool)) int {
	if len(args) == 1 && isFlagHelp(args[0]) {
		printXSSHUsage(stdout)
		return 0
	}
	if len(args) > 1 {
		fmt.Fprintln(stderr, "usage: warden xssh [connection]")
		return 2
	}

	cfg, err := loadClient(configPath, configPathSet, lookupEnv)
	if err != nil {
		fmt.Fprintf(stderr, "invalid client config: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "client bootstrap ready for xssh via %s\n", cfg.APIBaseURL)
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

	fmt.Fprintf(stdout, "client bootstrap ready for report create via %s\n", cfg.APIBaseURL)
	return 0
}

func runConfig(args []string, configPath string, configPathSet bool, stdout, stderr io.Writer, lookupEnv func(string) (string, bool)) int {
	if len(args) == 0 || isHelp(args[0]) {
		printConfigUsage(stdout)
		return 0
	}

	switch args[0] {
	case "list":
		if len(args) == 2 && isFlagHelp(args[1]) {
			printConfigListUsage(stdout)
			return 0
		}
		if len(args) != 1 {
			fmt.Fprintln(stderr, "usage: warden config list")
			return 2
		}
	case "get":
		if len(args) == 2 && isFlagHelp(args[1]) {
			printConfigGetUsage(stdout)
			return 0
		}
		if len(args) != 2 {
			fmt.Fprintln(stderr, "usage: warden config get <connection>")
			return 2
		}
	default:
		fmt.Fprintf(stderr, "unknown config command %q\n\n", args[0])
		printConfigUsage(stderr)
		return 2
	}

	cfg, err := loadClient(configPath, configPathSet, lookupEnv)
	if err != nil {
		fmt.Fprintf(stderr, "invalid client config: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "client bootstrap ready for config via %s\n", cfg.APIBaseURL)
	return 0
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
  warden [--config path] config list
  warden [--config path] config get <connection>
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
  warden config list
  warden config get <connection>
`)
}

func printConfigListUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  warden config list
`)
}

func printConfigGetUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  warden config get <connection>
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
