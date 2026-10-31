// Package client, ajanın sunucu (veya relay) ile konuştuğu HTTPS istemcisidir.
// Sunucu her zaman pin'lenmiş CA parmak izine göre doğrulanır.
package client

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/BerkayAtag/BerOps/shared/protocol"
	"github.com/BerkayAtag/BerOps/shared/tlspin"
)

// APIError, sunucunun döndürdüğü hata yanıtıdır.
type APIError struct {
	Status  int
	Code    string
	Message string
}

// StatusCode, HTTP durum kodunu döner.
func (e *APIError) StatusCode() int { return e.Status }

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

// UploadInventory, envanteri gzip ile sıkıştırarak gönderir.
func (c *Client) UploadInventory(ctx context.Context, r *protocol.InventoryReport) error {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zw).Encode(r); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base.JoinPath(protocol.PathInventory).String(), &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return readAPIError(resp)
	}
	return nil
}

// DownloadWSUSCab, çevrimdışı tarama kataloğunu dest yoluna indirir. Dosya zaten varsa
// yalnızca sunucudaki sürüm daha yeniyse indirilir; kesilen indirme .part dosyasından
// kaldığı yerden sürdürülür.
func (c *Client) DownloadWSUSCab(ctx context.Context, dest string) error {
	part := dest + ".part"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base.JoinPath(protocol.PathWSUSCab).String(), nil)
	if err != nil {
		return err
	}
	var offset int64
	if st, err := os.Stat(part); err == nil {
		offset = st.Size()
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	} else if st, err := os.Stat(dest); err == nil {
		req.Header.Set("If-Modified-Since", st.ModTime().UTC().Format(http.TimeFormat))
	}
	// Büyük dosya: genel 60 sn zaman aşımı yerine yalnızca bağlam kullanılır.
	hc := *c.http
	hc.Timeout = 0
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	flags := os.O_CREATE | os.O_WRONLY
	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil
	case http.StatusPartialContent:
		flags |= os.O_APPEND
	case http.StatusOK:
		flags |= os.O_TRUNC
	default:
		return readAPIError(resp)
	}
	f, err := os.OpenFile(part, flags, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		return fmt.Errorf("indirme yarıda kaldı (%d bayt sonra sürdürülecek): %w", offset, err)
	}
	if err := f.Close(); err != nil {
		return err
	}
	if lm, err := http.ParseTime(resp.Header.Get("Last-Modified")); err == nil {
		_ = os.Chtimes(part, lm, lm)
	}
	return os.Rename(part, dest)
}

func readAPIError(resp *http.Response) error {
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var e protocol.ErrorResponse
	_ = json.Unmarshal(data, &e)
	return &APIError{Status: resp.StatusCode, Code: e.Code, Message: e.Message}
}

// Jobs, bekleyen imzalı işleri alır.
func (c *Client) Jobs(ctx context.Context) ([]protocol.SignedJob, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base.JoinPath(protocol.PathJobs).String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, readAPIError(resp)
	}
	var out protocol.JobsResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&out); err != nil {
		return nil, err
	}
	return out.Jobs, nil
}

// JobStatus, işin durumunu bildirir.
func (c *Client) JobStatus(ctx context.Context, jobID string, r protocol.JobStatusRequest) error {
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.base.JoinPath(fmt.Sprintf(protocol.PathJobStatusFmt, url.PathEscape(jobID))).String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return readAPIError(resp)
	}
	return nil
}

// DownloadPackage, paket dosyasını dest yoluna indirir. Kesilen indirme dest.part dosyasından
// kaldığı yerden sürdürülür; sunucu istemci başına hız sınırını uygular.
func (c *Client) DownloadPackage(ctx context.Context, packageID, actionID, dest string) error {
	u := c.base.JoinPath(fmt.Sprintf(protocol.PathPackageFileFmt, url.PathEscape(packageID)))
	u.RawQuery = url.Values{"action": {actionID}}.Encode()
	part := dest + ".part"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	var offset int64
	if st, err := os.Stat(part); err == nil && st.Size() > 0 {
		offset = st.Size()
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	}
	hc := *c.http
	hc.Timeout = 0 // büyük dosya: yalnızca bağlam ile sınırlı
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	flags := os.O_CREATE | os.O_WRONLY
	switch resp.StatusCode {
	case http.StatusPartialContent:
		flags |= os.O_APPEND
	case http.StatusOK:
		flags |= os.O_TRUNC
	case http.StatusRequestedRangeNotSatisfiable:
		// .part dosyası sunucudakinden büyük veya bozuk: baştan indirilecek.
		_ = os.Remove(part)
		return fmt.Errorf("kısmi dosya geçersiz, yeniden indirilecek")
	default:
		return readAPIError(resp)
	}
	f, err := os.OpenFile(part, flags, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		return fmt.Errorf("indirme yarıda kaldı: %w", err)
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(part, dest)
}

// RemotePoll, uzaktan oturumdaki bir sonraki isteği uzun yoklamayla bekler; istek yoksa nil döner.
func (c *Client) RemotePoll(ctx context.Context) (*protocol.SignedJob, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base.JoinPath(protocol.PathRemotePoll).String(), nil)
	if err != nil {
		return nil, err
	}
	hc := *c.http
	hc.Timeout = 60 * time.Second // sunucu en fazla ~25 sn bekletir
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil, nil
	case http.StatusOK:
		var sj protocol.SignedJob
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&sj); err != nil {
			return nil, err
		}
		return &sj, nil
	}
	return nil, readAPIError(resp)
}

// RemoteResult, uzaktan isteğin sonucunu gönderir.
func (c *Client) RemoteResult(ctx context.Context, id string, r protocol.RemoteResult) error {
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.base.JoinPath(fmt.Sprintf(protocol.PathRemoteResultFmt, url.PathEscape(id))).String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return readAPIError(resp)
	}
	return nil
}
