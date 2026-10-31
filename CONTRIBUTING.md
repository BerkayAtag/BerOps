# Katkıda Bulunma

Automation BER'e katkıda bulunmak istediğiniz için teşekkürler. Bu belge geliştirme ortamını ve beklenen çalışma şeklini özetler.

## Geliştirme ortamı

- Go 1.27+
- Node.js 24+
- Docker (PostgreSQL için)

Kurulum adımları için [README.md](README.md) dosyasındaki "Hızlı başlangıç" bölümüne bakın.

## Dil

- Kod içi yorumlar, commit mesajları, dokümantasyon ve arayüz metinleri **Türkçe** yazılır.
- Kod tanımlayıcıları (değişken, fonksiyon, tablo adları) İngilizcedir.
- Arayüze eklenen her metin hem `console/src/i18n/locales/tr.json` hem `en.json` dosyasına eklenmelidir. Anahtar eşitliği testle denetlenir.

## Commit mesajları

[Conventional Commits](https://www.conventionalcommits.org/tr/) biçimi, Türkçe açıklamayla:

```
feat(ajan): heartbeat'e jitter eklendi
fix(sunucu): süresi dolan oturumlar temizlenmiyordu
docs(kurulum): macOS MDM adımları
```

Kapsamlar: `ajan`, `sunucu`, `konsol`, `relay`, `kurulum`, `ci`, `dokuman`, `deps`.

## Kod standartları

- **Go:** `gofmt`, `go vet` temiz olmalı. Hata mesajları Türkçe ve küçük harfle başlar.
- **TypeScript:** `npm run lint` (ESLint + Prettier) temiz olmalı.
- **Testler:** Yetkilendirme, transfer, imza doğrulama ve CVE eşleştirme modüllerinde birim testi zorunludur. Yeni API uç noktaları izin kontrolü testiyle birlikte gelir.
- **Güvenlik:** Repoya gerçek kimlik bilgisi, kurum adı, iç IP/alan adı veya özel anahtar eklenmez. Test anahtarları çalışma anında üretilir.
- **Veritabanı:** Şema değişiklikleri `server/internal/store/migrations/` altında yeni numaralı migration ile yapılır; mevcut migration'lar düzenlenmez.

## Pull request süreci

1. `main` dalından yeni bir dal açın.
2. Değişikliğinizi testleriyle birlikte yapın.
3. Yerelde `go test ./...` ve `npm --prefix console test -- --run` çalıştırın.
4. PR açıklamasında neyi neden değiştirdiğinizi ve nasıl test ettiğinizi yazın.
5. CI'ın (lint, testler, CodeQL) yeşil olması gerekir.
