package hostinfo

import (
	"runtime"
	"testing"
)

func TestCollectCachesOSInfo(t *testing.T) {
	calls := 0
	c := &Collector{platform: runtime.GOOS, readOS: func() OSInfo {
		calls++
		return OSInfo{Name: "Test OS", Version: "1", Build: "1.2.3"}
	}}
	a := c.Collect()
	b := c.Collect()
	if calls != 1 {
		t.Errorf("OS bilgisi önbelleğe alınmalı, %d kez okundu", calls)
	}
	if a.Hostname == "" || a.OSBuild != "1.2.3" || a.Arch != runtime.GOARCH || b.OSName != "Test OS" {
		t.Errorf("beklenmeyen bilgi: %+v", a)
	}
}

func TestReadOSInfoOnThisPlatform(t *testing.T) {
	info := readOSInfo()
	if info.Name == "" {
		t.Error("işletim sistemi adı boş olmamalı")
	}
	t.Logf("%+v", info)
}
