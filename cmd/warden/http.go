package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"

	"warden/internal/client/api"
	"warden/internal/model"
)

func runHTTP(args []string, configPath string, configPathSet bool, stdout, stderr io.Writer, lookupEnv func(string) (string, bool)) int {
	fs := flag.NewFlagSet("http", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {}
	contentType := fs.String("content-type", "", "upstream body media type (default application/json)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printHTTPUsage(stdout)
			return 0
		}
		return 2
	}
	rest := fs.Args()
	if len(rest) < 3 || len(rest) > 4 {
		printHTTPUsage(stderr)
		return 2
	}
	req := model.HTTPProxyRequest{Method: rest[0], Path: rest[2], ContentType: *contentType}
	if len(rest) == 4 {
		req.Body = []byte(rest[3])
		if req.ContentType == "" {
			req.ContentType = "application/json"
		}
	}
	if err := model.ValidateHTTPProxyRequest(req); err != nil {
		fmt.Fprintf(stderr, "http: %v\n", err)
		return 2
	}
	if len(req.Body) > model.HTTPMaxRequestBytes {
		fmt.Fprintln(stderr, "http: BODY exceeds 1 MiB")
		return 2
	}
	cfg, err := loadClient(configPath, configPathSet, lookupEnv)
	if err != nil {
		fmt.Fprintf(stderr, "invalid client config: %v\n", err)
		return 1
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	cl := api.New(cfg.APIBaseURL, &http.Client{Timeout: cfg.Timeout})
	conns, err := cl.ListHTTP(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "http: %v\n", err)
		return 1
	}
	var id int64
	for _, c := range conns {
		if c.Name == rest[1] && !c.Archived {
			id = c.ID
			break
		}
	}
	if id == 0 {
		fmt.Fprintf(stderr, "http: connection %q not found\n", rest[1])
		return 1
	}
	out, err := cl.RequestHTTP(ctx, id, req)
	if err != nil {
		fmt.Fprintf(stderr, "http: %v\n", err)
		return 1
	}
	if _, err := stdout.Write(out.Body); err != nil {
		fmt.Fprintf(stderr, "http: write response: %v\n", err)
		return 1
	}
	if out.StatusCode < 200 || out.StatusCode >= 300 {
		fmt.Fprintf(stderr, "http: upstream returned HTTP %d\n", out.StatusCode)
		return 1
	}
	return 0
}

func printHTTPUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  warden http [--content-type TYPE] METHOD CONNECTION PATH [BODY]

Send a request through the Warden server using a saved HTTP profile. PATH begins
with / and may include a query, but cannot change the configured origin or have
a fragment. METHOD is GET, HEAD, POST, PUT, PATCH, DELETE or OPTIONS. Quote BODY
as one argument; its default content type is application/json.

Saved credentials remain on the server. HTTP exposes credentials and body to
network interception; HTTPS certificates are verified. Redirects are not followed.
Requests are limited to 1 MiB, responses to 2 MiB, and server operations to 15s.
The upstream body is written unchanged to stdout (including on non-2xx). Non-2xx
upstream status is reported on stderr with exit status 1. Usage errors return 2.

Examples:
  warden http GET service '/v1/items?limit=10'
  warden http POST service /v1/items '{"name":"item"}'
  warden http --content-type text/plain PUT service /message 'hello'
`)
}
