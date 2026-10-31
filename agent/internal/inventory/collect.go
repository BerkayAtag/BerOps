package inventory

import (
	"context"
	"time"

	"github.com/BerkayAtag/BerOps/agent/internal/sysres"
	"github.com/BerkayAtag/BerOps/shared/protocol"
)

// Options, bir taramanın parametreleridir.
type Options struct {
	CPULimitPercent int
	// IncludeMissing, eksik yama taramasının (Windows Update / softwareupdate) yapılıp
	// yapılmayacağıdır. Ağ ve CPU açısından pahalı olduğu için yalnızca tam taramada yapılır.
	IncludeMissing bool
	// WSUSCabPath, boş değilse Windows'ta çevrimdışı tarama bu katalogla yapılır.
	WSUSCabPath string
}

// Snapshot, bir taramanın sonucudur. Collected, başarıyla toplanan bölümleri gösterir;
// toplanamayan bölümler gönderilmez ve sunucudaki önceki değer korunur.
type Snapshot struct {
	OS               *protocol.OSInventory
	InstalledPatches []protocol.InstalledPatch
	MissingPatches   []protocol.MissingPatch
	MissingScan      *protocol.MissingScanInfo
	Apps             []protocol.App
	Collected        map[string]bool
	Errors           []string
	Duration         time.Duration
}

func (s *Snapshot) fail(section string, err error) {
	s.Errors = append(s.Errors, section+": "+err.Error())
}

func (s *Snapshot) ok(section string) {
	s.Collected[section] = true
}

// Collect, platforma özgü toplayıcıyı çalıştırır ve sonuçları deterministik sıraya koyar.
func Collect(ctx context.Context, opts Options) *Snapshot {
	start := time.Now()
	s := &Snapshot{Collected: map[string]bool{}}
	th := sysres.NewThrottle(opts.CPULimitPercent)
	collectPlatform(ctx, opts, th, s)
	s.Apps = SortAndDedupeApps(s.Apps)
	s.InstalledPatches = SortInstalledPatches(s.InstalledPatches)
	s.MissingPatches = SortMissingPatches(s.MissingPatches)
	s.Duration = time.Since(start)
	return s
}
