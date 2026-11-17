// Package report implements the warden reports API client used by the CLI.
//
// Reports are immutable append-only changelog entries; this package never
// persists anything locally. It composes over the shared api.Client so all
// responses are strictly decoded, bounded, and sanitized by one code path.
package report

import (
	"context"
	"net/url"

	"warden/internal/client/api"
	"warden/internal/model"
)

// Client is a thin API-surface extension for report/project endpoints.
type Client struct {
	api *api.Client
}

// New returns a report client backed by the shared API client.
func New(cl *api.Client) *Client {
	return &Client{api: cl}
}

// ListProjects returns all projects ordered by name.
func (c *Client) ListProjects(ctx context.Context) ([]model.Project, error) {
	var out []model.Project
	err := c.api.GetJSON(ctx, "/api/v1/projects", &out)
	return out, err
}

// CreateProject creates a project or returns the existing one, giving a
// stable identifier for a given name (idempotent).
func (c *Client) CreateProject(ctx context.Context, name string) (model.Project, error) {
	var out model.Project
	err := c.api.PostJSON(ctx, "/api/v1/projects", model.ProjectRequest{Name: name}, &out)
	return out, err
}

// CreateReport appends an immutable report entry; created_at is assigned by
// the server.
func (c *Client) CreateReport(ctx context.Context, req model.ReportRequest) (model.Report, error) {
	var out model.Report
	err := c.api.PostJSON(ctx, "/api/v1/reports", req, &out)
	return out, err
}

// ListReports returns report entries for a project in chronological order.
func (c *Client) ListReports(ctx context.Context, project string) ([]model.Report, error) {
	var out []model.Report
	err := c.api.GetJSON(ctx, "/api/v1/projects/"+url.PathEscape(project)+"/reports", &out)
	return out, err
}
