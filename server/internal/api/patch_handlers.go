package api

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/BerkayAtag/BerOps/server/internal/store"
	"github.com/BerkayAtag/BerOps/shared/protocol"
)

var (
	// windowsUpdateID, Windows Update Agent güncelleme kimliğidir (GUID).
	windowsUpdateID = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)
	// macUpdateLabel, softwareupdate etiketidir (ör. "macOS Sonoma 14.7.1-23H222"). Tırnak ve
	// kabuk özel karakterleri kabul edilmez; komut tek tırnakla oluşturulur.
	macUpdateLabel = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._()+,:-]{0,199}$`)
)

// windowsPatchScript, verilen UpdateID'leri Windows Update Agent ile indirip kurar. Çıkış
// kodları: 0 başarılı, 3010 yeniden başlatma gerekli, 1 kurulum hatası.
const windowsPatchScript = `$ErrorActionPreference = 'Stop'
$ids = @(%s)
$session = New-Object -ComObject Microsoft.Update.Session
$session.ClientApplicationID = 'BerOps'
$result = $session.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0")
$updates = New-Object -ComObject Microsoft.Update.UpdateColl
foreach ($u in $result.Updates) {
  if ($ids -contains $u.Identity.UpdateID) {
    if (-not $u.EulaAccepted) { $u.AcceptEula() }
    [void]$updates.Add($u)
  }
}
if ($updates.Count -eq 0) {
  Write-Output 'Kurulacak güncelleme bulunamadı (zaten kurulu veya artık geçerli değil).'
  exit 0
}
Write-Output ('{0} güncelleme indiriliyor' -f $updates.Count)
$downloader = $session.CreateUpdateDownloader()
$downloader.Updates = $updates
[void]$downloader.Download()
$installer = $session.CreateUpdateInstaller()
$installer.Updates = $updates
$r = $installer.Install()
for ($i = 0; $i -lt $updates.Count; $i++) {
  Write-Output ('{0}: sonuç kodu {1}' -f $updates.Item($i).Title, $r.GetUpdateResult($i).ResultCode)
}
# ResultCode: 2 başarılı, 3 hatalarla başarılı, 4 başarısız, 5 iptal
if ($r.ResultCode -ne 2 -and $r.ResultCode -ne 3) { exit 1 }
if ($r.RebootRequired) { Write-Output 'Yeniden başlatma gerekli.'; exit 3010 }
exit 0`

// patchJob, platforma göre yama kurulum komutunu üretir.
func patchJob(platform string, ids []string) (shell, command string, successCodes []int, err error) {
	if len(ids) == 0 || len(ids) > 100 {
		return "", "", nil, errors.New("1-100 yama seçilmeli")
	}
	quoted := make([]string, len(ids))
	for i, id := range ids {
		switch platform {
		case protocol.PlatformWindows:
			if !windowsUpdateID.MatchString(id) {
				return "", "", nil, fmt.Errorf("geçersiz Windows güncelleme kimliği: %s", id)
			}
		case protocol.PlatformDarwin:
			if !macUpdateLabel.MatchString(id) {
				return "", "", nil, fmt.Errorf("geçersiz macOS güncelleme etiketi: %s", id)
			}
		}
		quoted[i] = "'" + id + "'"
	}
	switch platform {
	case protocol.PlatformWindows:
		return protocol.ShellPowerShell, fmt.Sprintf(windowsPatchScript, strings.Join(quoted, ", ")), []int{0, 3010}, nil
	case protocol.PlatformDarwin:
		// Yeniden başlatma gerektiren macOS güncellemeleri kurulur ama makine yeniden başlatılmaz.
		return protocol.ShellSh, "/usr/sbin/softwareupdate --install --agree-to-license " + strings.Join(quoted, " "), []int{0}, nil
	}
	return "", "", nil, fmt.Errorf("desteklenmeyen platform: %s", platform)
}

// handleListPatches, filodaki eksik yamaları güncelleme başına gruplar (kullanıcı kapsamına göre).
func (s *Server) handleListPatches(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	q := r.URL.Query()
	platform, severity := q.Get("platform"), q.Get("severity")
	if platform != "" && platform != protocol.PlatformWindows && platform != protocol.PlatformDarwin {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Geçersiz platform")
		return
	}
	items, err := s.store.FleetMissingPatches(r.Context(), platform, severity, q.Get("q"), sess.User.Scope())
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// handlePatchMachines, güncellemenin eksik olduğu makineleri döner.
func (s *Server) handlePatchMachines(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	id := r.URL.Query().Get("update_id")
	if id == "" || len(id) > 200 {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "update_id gerekli")
		return
	}
	items, err := s.store.PatchMachines(r.Context(), id, sess.User.Scope())
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}
