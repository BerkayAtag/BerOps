# API

BerOps iki ayrı HTTPS API sunar:

| API | Port | Kimlik doğrulama | Kullanıcı |
|---|---|---|---|
| Konsol API'si (`/api/v1`) | 8443 | Oturum çerezi + CSRF token | Konsol, dış sistemler |
| Ajan API'si (`/agent/v1`) | 52311 | mTLS (kayıt hariç) | Ajanlar, relay'ler |

Tam tanım OpenAPI 3.1 biçimindedir ve çalışan sunucudan alınabilir: `GET /api/openapi.yaml`. Kaynak dosya: [server/internal/api/openapi.yaml](../server/internal/api/openapi.yaml).

## Konsol API'si

### Oturum açma

```http
POST /api/v1/auth/login
Content-Type: application/json

{"username": "admin", "password": "…"}
```

Başarılı yanıt `__Host-ber_session` çerezini ayarlar ve kullanıcı bilgisini, izinlerini ve `csrf_token` değerini döner. Durum değiştiren tüm isteklerde (POST, PUT, PATCH, DELETE) bu değer `X-CSRF-Token` başlığında gönderilmelidir.

### Hata biçimi

Tüm hatalar aynı gövdeyi kullanır:

```json
{"code": "auth.forbidden", "message": "Bu işlem için yetkiniz yok"}
```

| Kod | HTTP | Anlamı |
|---|---|---|
| `auth.unauthenticated` | 401 | Oturum yok veya süresi dolmuş |
| `auth.invalid_credentials` | 401 | Kullanıcı adı veya parola hatalı |
| `auth.rate_limited` | 429 | Çok fazla başarısız deneme (`Retry-After` başlığına bakın) |
| `auth.forbidden` | 403 | Rolün bu işlem için izni yok |
| `auth.csrf` | 403 | CSRF token eksik veya hatalı |
| `request.invalid` | 400 | Gövde geçersiz |
| `request.unsupported_media_type` | 415 | `Content-Type: application/json` değil |
| `not_found` | 404 | Kayıt bulunamadı |
| `conflict` | 409 | Kayıt bu işleme uygun durumda değil |
| `auth.directory_unavailable` | 503 | Active Directory'ye ulaşılamıyor (yerel kurtarma hesabı kullanılabilir) |
| `auth.no_role_mapping` | 403 | AD kullanıcısı hiçbir grup eşlemesine uymuyor |
| `remote.disabled` / `remote.no_session` | 409 | Uzaktan yönetim özelliği kapalı / oturum açılmamış |
| `remote.failed` / `remote.timeout` | 422 / 504 | Uzaktan işlem ajanda başarısız oldu / ajan yanıt vermedi |

### İzinler

Her uç noktanın gerektirdiği izin OpenAPI tanımında `x-ber-permission` alanında yazılıdır. Rol–izin tablosu ve OU kapsamı: [roller-ve-yetkiler.md](roller-ve-yetkiler.md).

API anahtarlarıyla erişim (dış sistemler için) Aşama 5'te eklenecek.

## Ajan API'si

Ajan API'si yalnızca BerOps ajanları ve relay'ler içindir. Kayıt akışı ve güvenlik modeli için [mimari.md](mimari.md#32-ajan-kaydı-enrollment) dosyasına bakın.
