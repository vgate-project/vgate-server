package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"resty.dev/v3"

	"github.com/vgate-project/vgate-server/model"
)

// ErrNotModified is returned by FetchConfig/FetchUsers when the manager
// replies 304 Not Modified (the resource is unchanged since the last pull).
// It is non-fatal: the caller should keep its current config/users.
var ErrNotModified = errors.New("resource not modified")

type Client struct {
	BaseURL    string
	NodeID     string
	Token      string
	configETag string
	usersETag  string
	client     *resty.Client
}

func NewClient(baseURL, nodeID, token string) *Client {
	rc := resty.New().
		SetRetryCount(3).
		SetRetryWaitTime(5 * time.Second).
		SetRetryMaxWaitTime(5 * time.Second).
		SetRetryDefaultConditions(true).                  // retry on connection errors and 429
		SetRetryAllowNonIdempotent(true).                 // allow retrying POST (ReportTraffic keeps pending deltas)
		AddRetryConditions(resty.RetryConditionStatus5XX) // retry on HTTP 5xx
	return &Client{
		BaseURL: baseURL,
		NodeID:  nodeID,
		Token:   token,
		client:  rc,
	}
}

// FetchConfig pulls global configuration from the manager. On 304 it returns
// ErrNotModified and leaves the caller's current config in place.
func (c *Client) FetchConfig() (*model.Config, error) {
	req := c.client.R().
		SetQueryParam("node_id", c.NodeID).
		SetQueryParam("token", c.Token)
	if c.configETag != "" {
		req.SetHeader("If-None-Match", c.configETag)
	}
	resp, err := req.Get(c.BaseURL + "/config")
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() == http.StatusNotModified {
		return nil, ErrNotModified
	}
	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch config: status %d, %s", resp.StatusCode(), resp.String())
	}

	c.configETag = resp.Header().Get("ETag")
	var cfg model.Config
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// FetchUsers pulls the user set from the manager. On 304 it returns
// ErrNotModified and leaves the caller's current user set in place.
func (c *Client) FetchUsers() ([]model.User, error) {
	req := c.client.R().
		SetQueryParam("node_id", c.NodeID).
		SetQueryParam("token", c.Token)
	if c.usersETag != "" {
		req.SetHeader("If-None-Match", c.usersETag)
	}
	resp, err := req.Get(c.BaseURL + "/users")
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() == http.StatusNotModified {
		return nil, ErrNotModified
	}
	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch users: status %d, %s", resp.StatusCode(), resp.String())
	}

	c.usersETag = resp.Header().Get("ETag")
	var users []model.User
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		return nil, err
	}
	return users, nil
}

// ReportTraffic sends incremental (delta) user traffic statistics to the manager.
// Each UserTraffic entry represents the number of bytes transferred since the
// last successful report — NOT cumulative totals. On the receiving side these
// increments should be added to the user's stored total.
// If this call fails, the caller is expected to retain the pending deltas and
// merge them with the next cycle so no traffic is lost.
func (c *Client) ReportTraffic(traffic []model.UserTraffic) error {
	resp, err := c.client.R().
		SetQueryParam("node_id", c.NodeID).
		SetQueryParam("token", c.Token).
		SetBody(traffic).
		Post(c.BaseURL + "/traffic")
	if err != nil {
		return err
	}
	if resp.StatusCode() != http.StatusOK {
		return fmt.Errorf("failed to report traffic: status %d", resp.StatusCode())
	}
	return nil
}
