---
name: yeni-migration
description: server/ için numaralı PostgreSQL migration'ı (up/down) oluşturur, kuralları denetler ve geliştirme veritabanında dener. Kullanım: /yeni-migration <açıklama>
disable-model-invocation: true
---

# Yeni Migration

Argüman: `$ARGUMENTS` — migration'ın kısa açıklaması (ör. `paket kutuphanesi tablolari`).

## 1. Dosyaları oluştur

- Konum: `server/migrations/` (farklı bir klasör kullanılıyorsa onu bul ve ona uy).
- Ad: mevcut en yüksek numaranın bir fazlası, 6 hane, snake_case ve ASCII:
  `000012_paket_kutuphanesi.up.sql` ve `000012_paket_kutuphanesi.down.sql`
- Mevcut migration aracını (golang-migrate, goose vb.) koddan tespit et ve onun biçimine uy.

## 2. Kurallar

- Tablo ve kolon adları İngilizce, `snake_case`; açıklamalar `COMMENT ON` ile Türkçe.
- Birincil anahtar `uuid` (`gen_random_uuid()`), zaman alanları `timestamptz`.
- Her yabancı anahtar için index ekle; sık filtrelenen kolonlara (ör. `machine_id`, `cve_id`, `status`) index düşün.
- **Audit tablosu append-only kalmalı:** `audit_log` (veya karşılığı) üzerinde UPDATE ve DELETE'i engelleyen trigger var mı kontrol et; bu migration o tabloya dokunuyorsa trigger'ı koru.
- Gizli bilgiler (AD bağlantı şifresi, API anahtarları) asla düz metin kolon olmamalı: `bytea` olarak şifreli tutulur, API anahtarlarında yalnızca hash saklanır.
- RBAC kapsamları (OU / grup / etiket) için gereken ilişkileri unutma.
- `down.sql`, `up.sql`'i tamamen geri almalı.
- Gerçek kurum adı, IP veya kimlik bilgisi içeren seed verisi yazma.

## 3. Dene

Geliştirme veritabanı ayaktaysa (Docker Compose):

```bash
migrate -path server/migrations -database "$BER_DEV_DATABASE_URI" up
migrate -path server/migrations -database "$BER_DEV_DATABASE_URI" down 1
migrate -path server/migrations -database "$BER_DEV_DATABASE_URI" up
```

Postgres MCP bağlıysa şemayı onunla doğrula. Veritabanı ayakta değilse bunu kullanıcıya söyle ve SQL'i yalnızca gözden geçirerek bitir.

## 4. Bağlantılı güncellemeler

- `docs/mimari.md` içindeki veritabanı şeması bölümünü güncelle.
- Seed script'i yeni tabloları kullanıyorsa demo verisini ekle.
