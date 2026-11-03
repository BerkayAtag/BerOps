//go:build darwin

package jobs

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// updateLabel, güncellemeyi yürüten tek seferlik launchd işinin etiketidir. Ajandan ayrı bir
// iş olduğundan PKG'nin preinstall betiği ajanı durdurduğunda kurulum sürer.
const updateLabel = "io.github.berkayatag.berops.agent.update"

// updateScript, installer'ı çalıştırır ve çıkış kodunu dosyaya yazar ($1 paket, $2 günlük, $3 kod).
// Kod geçici dosyaya yazılıp taşınır; bekleyen taraf yarım yazılmış (boş) dosyayı okumaz.
const updateScript = `/usr/sbin/installer -pkg "$1" -target / >>"$2" 2>&1; echo $? >"$3.tmp" && mv -f "$3.tmp" "$3"`

func updatePlistPath(logFile string) string {
	return filepath.Join(filepath.Dir(logFile), "update.plist")
}

// StartUpdate, installer'ı launchd üzerinden ajandan bağımsız başlatır.
func StartUpdate(ctx context.Context, u UpdateSpec) (UpdateWait, error) {
	exitFile := u.LogFile + ".exit"
	_ = os.Remove(exitFile)
	_ = os.Remove(exitFile + ".tmp")
	_ = exec.Command("launchctl", "bootout", "system/"+updateLabel).Run()
	args := []string{"/bin/sh", "-c", updateScript, "sh", u.File, u.LogFile, exitFile}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>` + updateLabel + `</string>
<key>RunAtLoad</key><true/>
<key>ProgramArguments</key><array>
`)
	for _, a := range args {
		b.WriteString("<string>")
		if err := xml.EscapeText(&b, []byte(a)); err != nil {
			return nil, err
		}
		b.WriteString("</string>\n")
	}
	b.WriteString("</array></dict></plist>\n")
	plist := updatePlistPath(u.LogFile)
	if err := os.WriteFile(plist, []byte(b.String()), 0o644); err != nil {
		return nil, err
	}
	if out, err := exec.CommandContext(ctx, "launchctl", "bootstrap", "system", plist).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("launchctl bootstrap: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return func(ctx context.Context) (int, error) {
		for {
			if b, err := os.ReadFile(exitFile); err == nil {
				code, err := strconv.Atoi(strings.TrimSpace(string(b)))
				stopUpdateJob()
				return code, err
			}
			select {
			case <-ctx.Done():
				return -1, ctx.Err()
			case <-time.After(2 * time.Second):
			}
		}
	}, nil
}

// finishWait, yeni ajanın yükleyicinin bitmesini en çok bekleyeceği süredir.
const finishWait = 15 * time.Minute

// FinishUpdate, yükleyici bitince (çıkış kodu dosyası yazılınca) tek seferlik launchd işini
// kaldırır. PKG'nin postinstall betiği yeni ajanı installer bitmeden başlatır; iş hemen
// kaldırılırsa installer paket kaydını yazmadan sonlandırılabilir. Bekleme arka planda yapılır.
func FinishUpdate(logFile string) {
	go func() {
		exitFile := logFile + ".exit"
		deadline := time.Now().Add(finishWait)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(exitFile); err == nil {
				break
			}
			time.Sleep(2 * time.Second)
		}
		stopUpdateJob()
	}()
}

func stopUpdateJob() {
	_ = exec.Command("launchctl", "bootout", "system/"+updateLabel).Run()
}
