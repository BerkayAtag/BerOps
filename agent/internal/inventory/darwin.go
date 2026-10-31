//go:build darwin

package inventory

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/BerkayAtag/automation-ber/agent/internal/hostinfo"
	"github.com/BerkayAtag/automation-ber/agent/internal/sysres"
	"github.com/BerkayAtag/automation-ber/shared/protocol"
)

const softwareUpdateTimeout = 30 * time.Minute

func collectPlatform(ctx context.Context, opts Options, th *sysres.Throttle, s *Snapshot) {
	s.OS = macOSInventory(ctx, opts.IncludeMissing)
	s.ok(protocol.SectionOS)

	if data, err := os.ReadFile("/Library/Receipts/InstallHistory.plist"); err != nil {
		s.fail(protocol.SectionInstalledPatches, err)
	} else if ps, err := ParseInstallHistory(data); err != nil {
		s.fail(protocol.SectionInstalledPatches, err)
	} else {
		s.InstalledPatches = ps
		s.ok(protocol.SectionInstalledPatches)
	}

	apps, err := macApps(ctx, th)
	if err != nil {
		s.fail(protocol.SectionApps, err)
	} else {
		s.Apps = apps
		s.ok(protocol.SectionApps)
	}

	if opts.IncludeMissing && ctx.Err() == nil {
		sctx, cancel := context.WithTimeout(ctx, softwareUpdateTimeout)
		out, err := sysres.RunLowPriority(sctx, opts.CPULimitPercent, os.Environ(), "/usr/sbin/softwareupdate", "--list")
		cancel()
		if err != nil {
			s.fail(protocol.SectionMissingPatches, err)
			return
		}
		s.MissingPatches = ParseSoftwareUpdateList(string(out))
		s.MissingScan = &protocol.MissingScanInfo{Source: protocol.ScanSourceSoftwareUpdate, ScannedAt: time.Now().UTC()}
		s.ok(protocol.SectionMissingPatches)
	}
}

var serialRe = regexp.MustCompile(`"IOPlatformSerialNumber"\s*=\s*"([^"]+)"`)

func macOSInventory(ctx context.Context, withSerial bool) *protocol.OSInventory {
	osi := hostinfo.ReadOSInfo()
	inv := &protocol.OSInventory{
		Platform: protocol.PlatformDarwin, Name: osi.Name, Version: osi.Version, Build: osi.Build,
		Arch: runtime.GOARCH, Manufacturer: "Apple", CPUCores: runtime.NumCPU(),
	}
	inv.Model, _ = unix.Sysctl("hw.model")
	inv.CPUModel, _ = unix.Sysctl("machdep.cpu.brand_string")
	inv.MemoryBytes, _ = unix.SysctlUint64("hw.memsize")
	if tv, err := unix.SysctlTimeval("kern.boottime"); err == nil {
		t := time.Unix(tv.Sec, int64(tv.Usec)*1000).UTC()
		inv.LastBootAt = &t
	}
	if withSerial {
		if out, err := sysres.RunLowPriority(ctx, 0, nil, "/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice"); err == nil {
			if m := serialRe.FindSubmatch(out); m != nil {
				inv.SerialNumber = string(m[1])
			}
		}
	}
	return inv
}

// macApps, .app paketlerini, pkg makbuzlarını ve Homebrew paketlerini toplar.
func macApps(ctx context.Context, th *sysres.Throttle) ([]protocol.App, error) {
	var apps []protocol.App
	addBundles := func(root, scope string) {
		for _, p := range findAppBundles(root, 2) {
			if !th.Tick(ctx) {
				return
			}
			info := filepath.Join(p, "Contents", "Info.plist")
			data, err := os.ReadFile(info)
			if err != nil {
				continue
			}
			a, err := ParseInfoPlist(data, p)
			if err != nil {
				continue
			}
			a.Scope = scope
			if st, err := os.Stat(info); err == nil {
				a.InstallDate = st.ModTime().UTC().Format("2006-01-02")
			}
			apps = append(apps, a)
		}
	}
	addBundles("/Applications", "machine")
	if users, err := os.ReadDir("/Users"); err == nil {
		for _, u := range users {
			if u.IsDir() && u.Name() != "Shared" && !strings.HasPrefix(u.Name(), ".") {
				addBundles(filepath.Join("/Users", u.Name(), "Applications"), "user:"+u.Name())
			}
		}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	if receipts, err := filepath.Glob("/var/db/receipts/*.plist"); err == nil {
		for _, r := range receipts {
			if !th.Tick(ctx) {
				return nil, ctx.Err()
			}
			data, err := os.ReadFile(r)
			if err != nil {
				continue
			}
			if a, ok := ParseReceipt(data); ok {
				apps = append(apps, a)
			}
		}
	}

	for _, prefix := range []string{"/opt/homebrew", "/usr/local"} {
		apps = append(apps, ScanHomebrew(filepath.Join(prefix, "Cellar"), protocol.AppSourceHomebrew)...)
		apps = append(apps, ScanHomebrew(filepath.Join(prefix, "Caskroom"), protocol.AppSourceHomebrewCask)...)
	}
	return apps, ctx.Err()
}

// findAppBundles, root altında depth seviyeye kadar .app paketlerini bulur; bir paketin
// içine inmez (iç içe yardımcı uygulamalar ayrı sayılmaz).
func findAppBundles(root string, depth int) []string {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		p := filepath.Join(root, e.Name())
		if strings.HasSuffix(e.Name(), ".app") {
			out = append(out, p)
			continue
		}
		if e.IsDir() && depth > 1 && !strings.HasPrefix(e.Name(), ".") {
			out = append(out, findAppBundles(p, depth-1)...)
		}
	}
	return out
}
