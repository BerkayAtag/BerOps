package api

import (
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// staticHandler, derlenmiş konsolu sunar. Bilinmeyen yollar (istemci tarafı yönlendirme)
// index.html'e düşer. StaticDir tanımlı değilse kısa bir bilgi sayfası döner.
func (s *Server) staticHandler() http.Handler {
	dir := s.cfg.Console.StaticDir
	if dir == "" {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte("BerOps sunucusu çalışıyor. Konsol dosyaları yapılandırılmamış (console.static_dir).\n"))
		})
	}
	files := http.FileServer(http.Dir(dir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeError(w, http.StatusMethodNotAllowed, codeInvalidRequest, "Yönteme izin verilmiyor")
			return
		}
		clean := path.Clean("/" + r.URL.Path)
		if clean != "/" {
			if info, err := os.Stat(filepath.Join(dir, filepath.FromSlash(clean))); err == nil && !info.IsDir() {
				// Vite derlemesindeki dosya adları içerik özeti taşır; uzun süre önbelleklenebilir.
				if strings.HasPrefix(clean, "/assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				}
				files.ServeHTTP(w, r)
				return
			}
		}
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeFile(w, r, filepath.Join(dir, "index.html"))
	})
}
