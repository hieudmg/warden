package api

import (
	"context"
	"net/http"
	"strconv"

	"warden/internal/model"
)

const httpConnectionsPath = "/api/v1/http-connections"

func httpConnectionPath(id int64) string {
	return httpConnectionsPath + "/" + strconv.FormatInt(id, 10)
}

func (c *Client) ListHTTP(ctx context.Context) ([]model.HTTPConnection, error) {
	var out []model.HTTPConnection
	err := c.getJSON(ctx, httpConnectionsPath, &out)
	return out, err
}
func (c *Client) GetHTTP(ctx context.Context, id int64) (model.HTTPConnection, error) {
	var out model.HTTPConnection
	err := c.getJSON(ctx, httpConnectionPath(id), &out)
	return out, err
}
func (c *Client) CreateHTTP(ctx context.Context, req model.HTTPConnectionRequest) (model.HTTPConnection, error) {
	var out model.HTTPConnection
	err := c.requestJSON(ctx, http.MethodPost, httpConnectionsPath, req, &out, http.StatusCreated)
	return out, err
}
func (c *Client) UpdateHTTP(ctx context.Context, id int64, req model.HTTPConnectionRequest) (model.HTTPConnection, error) {
	var out model.HTTPConnection
	err := c.requestJSON(ctx, http.MethodPut, httpConnectionPath(id), req, &out, http.StatusOK)
	return out, err
}
func (c *Client) DeleteHTTP(ctx context.Context, id int64) error {
	return c.requestJSON(ctx, http.MethodDelete, httpConnectionPath(id), nil, nil, http.StatusNoContent)
}
func (c *Client) SetHTTPArchived(ctx context.Context, id int64, archived bool) error {
	var out struct {
		Archived bool `json:"archived"`
	}
	return c.requestJSON(ctx, http.MethodPut, httpConnectionPath(id)+"/archive", map[string]bool{"archived": archived}, &out, http.StatusOK)
}

// RequestHTTP distinguishes Warden API errors from an upstream status, which
// is always returned in the successful envelope, even for upstream non-2xx.
func (c *Client) RequestHTTP(ctx context.Context, id int64, req model.HTTPProxyRequest) (model.HTTPProxyResponse, error) {
	var out model.HTTPProxyResponse
	err := c.requestJSON(ctx, http.MethodPost, httpConnectionPath(id)+"/request", req, &out, http.StatusOK)
	return out, err
}
