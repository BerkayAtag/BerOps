# BerOps — Claude Code notları

Ajan tabanlı yama yönetim platformu. Spesifikasyonun aşamaları README'deki yol haritasındadır; mimari: `docs/mimari.md`, varsayımlar: `docs/varsayimlar.md`.

## Kurallar

- Dokümantasyon, yorumlar, commit mesajları ve arayüz metinleri Türkçe; kod tanımlayıcıları İngilizce.
- Marka adı repoda geçmez; renkler yalnızca `design/tokens.css` içindeki `--ber-*` token'larıyla kullanılır.
- Yetki kontrolü her API uç noktasında sunucu tarafında (`authed(perm, …)`) yapılır; arayüzdeki kontrol yalnızca kullanıcı deneyimi içindir.
- Yeni arayüz metni hem `tr.json` hem `en.json` dosyasına eklenir.
- Şema değişikliği = yeni numaralı migration (`server/internal/store/migrations/`); mevcutlar düzenlenmez.
- Belirsiz bir noktada makul varsayım yap ve `docs/varsayimlar.md` dosyasına yaz.

## Komutlar

- Geliştirme veritabanı: `docker compose -f deploy/docker-compose.dev.yml up -d --wait`
- Go testleri: `BER_TEST_DATABASE_URL='postgres://ber:ber@localhost:5432/postgres?sslmode=disable' go test -race ./...`
- Konsol: `npm --prefix console run lint`, `npm --prefix console test -- --run`, `npm --prefix console run build`
- Aşama kapatma: `/asama-tamamla <no> <başlık>`
