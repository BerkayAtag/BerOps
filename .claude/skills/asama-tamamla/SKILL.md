---
name: asama-tamamla
description: Bir geliştirme aşamasını kapatır — Go ve konsol derleme/test/lint, i18n eşitliği, CHANGELOG, varsayımlar ve Türkçe commit. Kullanım: /asama-tamamla <aşama no> <kısa başlık>
disable-model-invocation: true
---

# Aşama Kapısı

Argüman: `$ARGUMENTS` (ör. `1 Temel altyapı`). Aşama numarası verilmediyse sor.

Bir adım başarısız olursa **dur**, hatayı kullanıcıya göster ve düzeltmeden commit'e geçme.
Bir bileşen henüz yoksa (ör. `relay/` klasörü oluşmamışsa) o adımı atla ve özette "atlandı" diye belirt.

## 1. Go bileşenleri

`agent/`, `server/`, `relay/` içinde `go.mod` bulunan her modül için:

```bash
gofmt -l .            # çıktı boş olmalı
go vet ./...
go test -race ./...
go build ./...
```

Ajan için çapraz derlemeyi de doğrula:

```bash
GOOS=windows GOARCH=amd64 go build -o /dev/null ./cmd/...
GOOS=darwin  GOARCH=arm64 go build -o /dev/null ./cmd/...
GOOS=darwin  GOARCH=amd64 go build -o /dev/null ./cmd/...
```

## 2. Konsol ve tanıtım sayfası

`console/` ve `landing/` içinde `package.json` varsa:

```bash
npm run lint
npm test -- --run     # vitest kullanılıyorsa
npm run build
```

## 3. i18n eşitliği

`console/src/i18n/` (veya projedeki karşılığı) altındaki `tr` ve `en` dosyalarının anahtar kümelerini `jq` ile karşılaştır. Eksik anahtar varsa listele ve tamamla. Türkçe varsayılan dildir.

## 4. Güvenlik kontrolü

Aşama yetkilendirme, transfer, imza doğrulama, CVE eşleştirme veya uzaktan yönetim içeriyorsa `guvenlik-denetcisi` subagent'ını bu aşamanın değişiklikleri üzerinde çalıştır. Kritik bulgu varsa commit'ten önce düzelt.

## 5. Dokümantasyon

- `CHANGELOG.md` içinde `## [Yayımlanmamış]` başlığı altına bu aşamanın Türkçe özetini ekle (Eklendi / Değişti / Düzeltildi).
- Bu aşamada yapılan varsayımları `docs/varsayimlar.md` dosyasına işle.
- Platform kısıtı nedeniyle kısmen yapılan özellikleri açıkça not et.

## 6. Commit

Değişiklikleri göster, ardından Türkçe Conventional Commits biçiminde commit at:

```
feat(asama-<no>): <kısa başlık>

- <madde madde ne eklendi>
```

Kapsam örnekleri: `ajan`, `sunucu`, `konsol`, `relay`, `kurulum`, `ci`, `dokuman`.
Push yapma; kullanıcı ayrıca isterse yap.

## 7. Özet

Kullanıcıya şu tabloyu ver: bileşen, derleme, test, lint, durum (geçti / atlandı / başarısız).
