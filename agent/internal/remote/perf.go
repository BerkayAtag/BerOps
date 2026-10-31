package remote

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/process"

	"github.com/BerkayAtag/automation-ber/shared/protocol"
)

// sampleWindow, CPU kullanımının ölçüldüğü aralıktır.
const sampleWindow = time.Second

// topProcesses, döndürülen en fazla süreç sayısıdır.
const topProcesses = 15

// Performance, CPU, bellek, disk ve en çok kaynak kullanan süreçleri toplar. CPU kullanımı
// (sistem ve süreç bazında) bir saniyelik aralıkta iki ölçüm arasındaki farktan hesaplanır.
func Performance(ctx context.Context) (*protocol.PerfSnapshot, error) {
	snap := &protocol.PerfSnapshot{CollectedAt: time.Now().UTC(), Disks: []protocol.DiskUsage{}, Processes: []protocol.ProcessInfo{}}
	snap.CPUCores, _ = cpu.CountsWithContext(ctx, true)

	procs, _ := process.ProcessesWithContext(ctx)
	before := map[int32]float64{}
	for _, p := range procs {
		if t, err := p.TimesWithContext(ctx); err == nil {
			before[p.Pid] = t.User + t.System
		}
	}
	start := time.Now()
	pct, err := cpu.PercentWithContext(ctx, sampleWindow, false)
	if err == nil && len(pct) > 0 {
		snap.CPUPercent = round1(pct[0])
	}
	elapsed := time.Since(start).Seconds()

	type sample struct {
		p   *process.Process
		cpu float64
		rss uint64
	}
	var samples []sample
	for _, p := range procs {
		t, err := p.TimesWithContext(ctx)
		if err != nil {
			continue
		}
		prev, ok := before[p.Pid]
		if !ok {
			continue
		}
		c := (t.User + t.System - prev) / elapsed * 100
		var rss uint64
		if mi, err := p.MemoryInfoWithContext(ctx); err == nil {
			rss = mi.RSS
		}
		samples = append(samples, sample{p: p, cpu: max(c, 0), rss: rss})
	}
	// Önce CPU'ya, eşitlikte belleğe göre sıralanır.
	slices.SortFunc(samples, func(a, b sample) int {
		switch {
		case a.cpu > b.cpu+0.05:
			return -1
		case b.cpu > a.cpu+0.05:
			return 1
		case a.rss > b.rss:
			return -1
		case b.rss > a.rss:
			return 1
		}
		return 0
	})
	for _, sm := range samples[:min(len(samples), topProcesses)] {
		name, _ := sm.p.NameWithContext(ctx)
		user, _ := sm.p.UsernameWithContext(ctx)
		snap.Processes = append(snap.Processes, protocol.ProcessInfo{PID: sm.p.Pid, Name: name, User: user,
			CPUPercent: round1(sm.cpu), RSS: sm.rss})
	}

	if vm, err := mem.VirtualMemoryWithContext(ctx); err == nil {
		snap.MemTotal, snap.MemUsed = vm.Total, vm.Used
	}
	if sw, err := mem.SwapMemoryWithContext(ctx); err == nil {
		snap.SwapTotal, snap.SwapUsed = sw.Total, sw.Used
	}
	if up, err := host.UptimeWithContext(ctx); err == nil {
		snap.UptimeSeconds = up
	}
	parts, _ := disk.PartitionsWithContext(ctx, false)
	seen := map[string]bool{}
	for _, p := range parts {
		if skipMount(p.Mountpoint, p.Fstype) || seen[p.Mountpoint] {
			continue
		}
		seen[p.Mountpoint] = true
		u, err := disk.UsageWithContext(ctx, p.Mountpoint)
		if err != nil || u.Total == 0 {
			continue
		}
		snap.Disks = append(snap.Disks, protocol.DiskUsage{Mount: p.Mountpoint, FSType: p.Fstype, Total: u.Total, Used: u.Used})
	}
	return snap, nil
}

// skipMount, kullanıcıya anlamsız sistem birimlerini (macOS sistem bölümleri, sanal FS) atlar.
func skipMount(mount, fs string) bool {
	switch fs {
	case "devfs", "autofs", "nullfs", "tmpfs", "procfs", "overlay":
		return true
	}
	if strings.HasPrefix(mount, "/System/Volumes/") && mount != "/System/Volumes/Data" {
		return true
	}
	return strings.HasPrefix(mount, "/private/var/vm") || strings.HasPrefix(mount, "/Library/Developer")
}

func round1(v float64) float64 { return float64(int64(v*10+0.5)) / 10 }
