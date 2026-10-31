// Package hostinfo, heartbeat'te gönderilen hafif makine bilgisini toplar. İşletim sistemi
// bilgisi pahalı olabildiği için önbelleğe alınır; hostname ve IP'ler her seferinde okunur.
package hostinfo

import (
	"net"
	"os"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/BerkayAtag/automation-ber/shared/protocol"
	"github.com/BerkayAtag/automation-ber/shared/version"
)

// OSInfo, işletim sistemi adı, sürümü ve yama seviyesidir.
type OSInfo struct {
	Name    string
	Version string
	// Build, yama seviyesidir: Windows'ta 10.0.22631.4460, macOS'ta 24B83 gibi.
	Build string
}

const osInfoTTL = time.Hour

// Collector, makine bilgisini toplar.
type Collector struct {
	mu       sync.Mutex
	os       OSInfo
	osAt     time.Time
	readOS   func() OSInfo
	platform string
}

// New, çalışılan platform için toplayıcı döner.
func New() *Collector {
	return &Collector{readOS: readOSInfo, platform: runtime.GOOS}
}

// Collect, güncel makine bilgisini döner.
func (c *Collector) Collect() protocol.HostInfo {
	c.mu.Lock()
	if c.osAt.IsZero() || time.Since(c.osAt) > osInfoTTL {
		c.os = c.readOS()
		c.osAt = time.Now()
	}
	osi := c.os
	c.mu.Unlock()

	hostname, _ := os.Hostname()
	return protocol.HostInfo{
		Hostname:     hostname,
		OSPlatform:   c.platform,
		OSName:       osi.Name,
		OSVersion:    osi.Version,
		OSBuild:      osi.Build,
		Arch:         runtime.GOARCH,
		IPAddresses:  IPAddresses(),
		AgentVersion: version.Version,
	}
}

// IPAddresses, etkin arayüzlerdeki geri döngü ve bağlantı-yerel olmayan adreslerdir.
func IPAddresses() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.IsLoopback() || ipn.IP.IsLinkLocalUnicast() || ipn.IP.IsLinkLocalMulticast() {
				continue
			}
			out = append(out, ipn.IP.String())
		}
	}
	sort.Strings(out)
	if len(out) > 16 {
		out = out[:16]
	}
	return out
}
