//go:build windows

package inventory

import (
	"context"
	_ "embed"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows/registry"

	"github.com/BerkayAtag/BerOps/agent/internal/hostinfo"
	"github.com/BerkayAtag/BerOps/agent/internal/sysres"
	"github.com/BerkayAtag/BerOps/shared/protocol"
)

//go:embed scripts/system.ps1
var systemScript string

//go:embed scripts/wua.ps1
var wuaScript string

const (
	uninstallPath    = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
	userUninstallSub = `Software\Microsoft\Windows\CurrentVersion\Uninstall`
	systemTimeout    = 5 * time.Minute
	wuaTimeout       = 45 * time.Minute
)

func powershellPath() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
}

// runPowerShell, betiği -EncodedCommand ile (UTF-16LE base64) çalıştırır; böylece betik
// diske yazılmaz ve tırnak/kaçış sorunları oluşmaz.
func runPowerShell(ctx context.Context, cpuLimit int, script string, extraEnv ...string) ([]byte, error) {
	u := utf16.Encode([]rune(script))
	b := make([]byte, len(u)*2)
	for i, c := range u {
		b[2*i], b[2*i+1] = byte(c), byte(c>>8)
	}
	env := append(os.Environ(), extraEnv...)
	return sysres.RunLowPriority(ctx, cpuLimit, env, powershellPath(),
		"-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-EncodedCommand", base64.StdEncoding.EncodeToString(b))
}

func collectPlatform(ctx context.Context, opts Options, th *sysres.Throttle, s *Snapshot) {
	// Sistem betiği KB listesini, donanım bilgisini ve AppX paketlerini tek seferde toplar.
	sctx, cancel := context.WithTimeout(ctx, systemTimeout)
	out, err := runPowerShell(sctx, opts.CPULimitPercent, systemScript, "BER_INCLUDE_APPX=1")
	cancel()
	var si *SystemInfo
	if err == nil {
		si, err = ParseSystemInfo(out)
	}
	if err != nil {
		s.fail(protocol.SectionInstalledPatches, err)
	}

	// İşletim sistemi
	osi := hostinfo.ReadOSInfo()
	inv := &protocol.OSInventory{
		Platform: protocol.PlatformWindows, Name: osi.Name, Version: osi.Version, Build: osi.Build,
		Arch: runtime.GOARCH, CPUCores: runtime.NumCPU(),
		ADDN: readMachineDN(), RebootPending: rebootPending(),
	}
	if si != nil {
		inv.Manufacturer, inv.Model, inv.SerialNumber = si.Manufacturer, si.Model, si.Serial
		inv.CPUModel, inv.MemoryBytes = strings.TrimSpace(si.CPU), si.Memory
		if si.PartOfDomain {
			inv.Domain = si.Domain
		}
		if t, err := time.Parse(time.RFC3339, si.LastBoot); err == nil {
			t = t.UTC()
			inv.LastBootAt = &t
		}
		s.InstalledPatches = si.HotfixPatches()
		s.ok(protocol.SectionInstalledPatches)
	}
	s.OS = inv
	s.ok(protocol.SectionOS)

	// Uygulamalar: kayıt defteri (64/32 bit, makine ve kullanıcılar) + AppX
	apps, err := registryApps(ctx, th)
	if err != nil {
		s.fail(protocol.SectionApps, err)
	} else {
		if si != nil {
			apps = append(apps, si.AppXApps()...)
		}
		s.Apps = apps
		s.ok(protocol.SectionApps)
	}

	if opts.IncludeMissing && ctx.Err() == nil {
		var env []string
		if opts.WSUSCabPath != "" {
			env = append(env, "BER_WSUS_CAB="+opts.WSUSCabPath)
		}
		wctx, cancel := context.WithTimeout(ctx, wuaTimeout)
		out, err := runPowerShell(wctx, opts.CPULimitPercent, wuaScript, env...)
		cancel()
		if err != nil {
			s.fail(protocol.SectionMissingPatches, err)
			return
		}
		patches, source, err := ParseWUAResult(out)
		if err != nil {
			s.fail(protocol.SectionMissingPatches, err)
			return
		}
		if source != protocol.ScanSourceOffline {
			source = protocol.ScanSourceOnline
		}
		s.MissingPatches = patches
		s.MissingScan = &protocol.MissingScanInfo{Source: source, ScannedAt: time.Now().UTC()}
		s.ok(protocol.SectionMissingPatches)
	}
}

var userSIDRe = regexp.MustCompile(`^S-1-5-21-[\d-]+$`)

func registryApps(ctx context.Context, th *sysres.Throttle) ([]protocol.App, error) {
	var apps []protocol.App
	add := func(root registry.Key, path string, access uint32, arch, scope string) error {
		k, err := registry.OpenKey(root, path, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE|access)
		if err != nil {
			if errors.Is(err, registry.ErrNotExist) {
				return nil
			}
			return err
		}
		defer k.Close()
		names, err := k.ReadSubKeyNames(-1)
		if err != nil {
			return err
		}
		for _, n := range names {
			if !th.Tick(ctx) {
				return ctx.Err()
			}
			e, ok := readUninstallEntry(k, n)
			if !ok {
				continue
			}
			e.Arch, e.Scope = arch, scope
			if a, ok := NormalizeUninstall(e); ok {
				apps = append(apps, a)
			}
		}
		return nil
	}

	if err := add(registry.LOCAL_MACHINE, uninstallPath, registry.WOW64_64KEY, "x64", "machine"); err != nil {
		return nil, err
	}
	if err := add(registry.LOCAL_MACHINE, uninstallPath, registry.WOW64_32KEY, "x86", "machine"); err != nil {
		return nil, err
	}
	// Oturumu açık (hive'ı yüklü) kullanıcıların kendi profillerine kurdukları uygulamalar.
	users, err := registry.USERS.ReadSubKeyNames(-1)
	if err == nil {
		for _, sid := range users {
			if userSIDRe.MatchString(sid) {
				_ = add(registry.USERS, sid+`\`+userUninstallSub, 0, "", "user:"+sid)
			}
		}
	}
	return apps, nil
}

func readUninstallEntry(parent registry.Key, name string) (UninstallEntry, bool) {
	k, err := registry.OpenKey(parent, name, registry.QUERY_VALUE)
	if err != nil {
		return UninstallEntry{}, false
	}
	defer k.Close()
	str := func(v string) string {
		s, _, _ := k.GetStringValue(v)
		return s
	}
	num := func(v string) uint64 {
		n, _, _ := k.GetIntegerValue(v)
		return n
	}
	return UninstallEntry{
		KeyName:          name,
		DisplayName:      str("DisplayName"),
		DisplayVersion:   str("DisplayVersion"),
		Publisher:        str("Publisher"),
		InstallDate:      str("InstallDate"),
		InstallLocation:  str("InstallLocation"),
		ReleaseType:      str("ReleaseType"),
		ParentKeyName:    str("ParentKeyName"),
		SystemComponent:  num("SystemComponent"),
		WindowsInstaller: num("WindowsInstaller"),
	}, true
}

// readMachineDN, Grup İlkesi'nin kaydettiği bilgisayar ayırt edici adını okur
// (ör. CN=PC01,OU=İzmir,DC=corp,DC=example). Etki alanında değilse boş döner.
func readMachineDN() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	dn, _, _ := k.GetStringValue("Distinguished-Name")
	return dn
}

// rebootPending, Windows'un yeniden başlatma beklediğini gösteren kayıt defteri işaretlerini denetler.
func rebootPending() bool {
	keyExists := func(path string) bool {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
		if err != nil {
			return false
		}
		k.Close()
		return true
	}
	if keyExists(`SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`) ||
		keyExists(`SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending`) {
		return true
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetStringsValue("PendingFileRenameOperations")
	return err == nil && len(v) > 0
}
