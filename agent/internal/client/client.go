// Package client, ajanın sunucu (veya relay) ile konuştuğu HTTPS istemcisidir.
// Sunucu her zaman pin'lenmiş CA parmak izine göre doğrulanır.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/BerkayAtag/automation-ber/shared/protocol"
	"github.com/BerkayAtag/automation-ber/shared/tlspin"
)

// APIError, sunucunun döndürdüğü hata yanıtıdır.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("sunucu %d döndü: %s (%s)", e.Status, e.Message, e.Code)
}

// Client, ajan API istemcisidir.
type Client struct {
	base *url.URL
	http *http.Client
}

// New, istemci oluşturur. cert nil ise istemci sertifikası gönderilmez (yalnızca kayıt için).
func New(serverURL, caHash string, cert *tls.Certificate) (*Client, error) {
	u, err := url.Parse(serverURL)
	if err != nil || u.Scheme != "https" {
		return nil, fmt.Errorf("sunucu adresi geçersiz: %q", serverURL)
	}
	tc, err := tlspin.Config(caHash, u.Hostname())
	if err != nil {
		return nil, err
	}
	if cert != nil {
		tc.Certificates = []tls.Certificate{*cert}
	}
	tr := &http.Transport{
		TLSClientConfig:     tc,
		Proxy:               http.ProxyFromEnvironment,
		MaxIdleConns:        2,
		IdleConnTimeout:     5 * time.Minute,
		TLSHandshakeTimeout: 15 * time.Second,
	}
	return &Client{base: u, http: &http.Client{Transport: tr, Timeout: 60 * time.Second}}, nil
}

// Enroll, kayıt isteği gönderir.
func (c *Client) Enroll(ctx context.Context, req protocol.EnrollRequest) (*protocol.EnrollResponse, error) {
	var out protocol.EnrollResponse
	if err := c.post(ctx, protocol.PathEnroll, req, http.StatusCreated, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Heartbeat, heartbeat gönderir.
func (c *Client) Heartbeat(ctx context.Context, req protocol.HeartbeatRequest) (*protocol.HeartbeatResponse, error) {
	var out protocol.HeartbeatResponse
	if err := c.post(ctx, protocol.PathHeartbeat, req, http.StatusOK, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CloseIdle, boştaki bağlantıları kapatır (heartbeat aralarında soket tutmamak için).
func (c *Client) CloseIdle() { c.http.CloseIdleConnections() }

func (c *Client) post(ctx context.Context, path string, in any, want int, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base.JoinPath(path).String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != want {
		var e protocol.ErrorResponse
		_ = json.Unmarshal(data, &e)
		return &APIError{Status: resp.StatusCode, Code: e.Code, Message: e.Message}
	}
	return json.Unmarshal(data, out)
}
