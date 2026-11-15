package main

import (
	"context"
	"fmt"
	"io"
	"time"

	"warden/internal/client/agent"
	"warden/internal/client/api"
	"warden/internal/client/terminal"
	"warden/internal/config"
)

var newAPIClient = func(cfg config.Client) *api.Client {
	return api.NewAgent(cfg.APIBaseURL, cfg.CACertificate, cfg.Timeout)
}
var agentAuthorization = agent.Authorization

func runAuthorization(args []string, configPath string, configPathSet bool, stdout, stderr io.Writer, lookupEnv func(string) (string, bool), mode outputMode) int {
	if len(args) == 2 && isFlagHelp(args[1]) {
		fmt.Fprintln(stdout, "usage: warden login|logout|status\nlogin: fresh web passkey approval, bounded to five minutes; -n prints approval steps and exits if pending.\nlogout: attempt server revocation then clear agent memory, even offline; agent stays alive.\nstatus: check current authorization, not an unlock operation. Agent restart needs new approval; server restart remains authorized but locked.")
		return 0
	}
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: warden login|logout|status")
		return 2
	}
	cfg, err := loadClient(configPath, configPathSet, lookupEnv)
	if err != nil {
		fmt.Fprintf(stderr, "invalid client config: %v\n", terminal.ErrorText(err))
		return 1
	}
	action := args[0]
	if action == "login" {
		action = "begin"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	e, err := agentAuthorization(ctx, cfg.APIBaseURL, cfg.CACertificate, cfg.Timeout, action, "")
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", args[0], terminal.ErrorText(err))
		return 1
	}
	if args[0] != "login" {
		fmt.Fprintln(stdout, e.Status)
		return 0
	}
	if e.Status == "approved" {
		fmt.Fprintln(stdout, "Client authorized. Vault unlock remains a separate web action.")
		return 0
	}
	fmt.Fprintf(stdout, "Web approval required: %s\nDevice: %s\nRequest: %s\nFingerprint: %s\nLog in with your passkey, compare this fingerprint and approve this exact device. No API secret is displayed.\n", e.ApprovalURL, e.Label, e.ID, e.Fingerprint)
	if mode == outputModeNonInteractive {
		fmt.Fprintln(stderr, "Approval pending. Approve in the browser, then run warden login again; non-interactive login never waits for human input.")
		return 1
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			fmt.Fprintln(stderr, "Approval expired or cancelled; run warden login again.")
			return 1
		case <-ticker.C:
			e, err = agentAuthorization(ctx, cfg.APIBaseURL, cfg.CACertificate, cfg.Timeout, "poll", "")
			if err != nil {
				fmt.Fprintln(stderr, terminal.ErrorText(err))
				return 1
			}
			if e.Status == "approved" {
				fmt.Fprintln(stdout, "Client authorized. Agent retains credential in memory only.")
				return 0
			}
			if e.Status != "pending" {
				fmt.Fprintln(stderr, "Approval denied or expired; run warden login again.")
				return 1
			}
		}
	}
}
