# BER Relay

Şubeler ve ayrı ağ segmentleri için önbellekleyen dağıtım noktası. Ajanlar sunucu yerine relay'e bağlanır; relay istekleri sunucuya iletir, paket dosyalarını ise bir kez indirip şubedeki tüm makinelere yerelden verir.

```
 Şube ağı                                     Merkez
┌──────────┐  mTLS (ajan sert.)  ┌─────────┐  mTLS (relay sert.)  ┌────────────┐
│ BER Agent├────────────────────►│BER Relay├─────────────────────►│ BER Server │
└──────────┘      :52311         │ önbellek│       :52311         └────────────┘
                                 └─────────┘
```

## Nasıl çalışır?

- **TLS:** Relay, ajan bağlantısını kendi sertifikasıyla sonlandırır. Relay sertifikası iç CA tarafından imzalanır ve zincirde CA bulunur; ajanların sabitlediği CA parmak izi değişmez.
- **Kimlik:** Relay, ajanın istemci sertifikasını iç CA'ya göre doğrular ve sunucuya `X-Ber-Agent-Cert` başlığıyla iletir. Sunucu bu başlığa **yalnızca relay sertifikasıyla** gelen bağlantılarda güvenir, sertifikayı yeniden doğrular ve iptal kayıtlarını denetler. Ajanın kendisinin gönderdiği bu tür başlıklar relay'de silinir.
- **Kayıt, heartbeat, envanter, işler:** Değiştirilmeden sunucuya iletilir.
- **Paket indirme:** Relay önce sunucuya yetki sorar (`X-Ber-Relay-Probe`). Sunucu, bu makine için açık bir dağıtım varsa dosyanın SHA-256 özetini, boyutunu ve istemci başına hız sınırını döner. Dosya önbellekte yoksa relay onu `/agent/v1/relay/files/{sha256}` uç noktasından **bir kez** indirir, özeti doğrular ve önbelleğe koyar. Aynı anda gelen istekler tek indirmeyi bekler. Ajana dosya, sunucunun belirlediği hız sınırıyla ve `Range` desteğiyle verilir.
- **Önbellek:** Varsayılan üst sınır 50 GB'tır. Sınır aşılınca en uzun süredir kullanılmayan dosyalar silinir.
- **İptal:** Konsolda Ayarlar → Relay sunucuları sayfasından relay sertifikası iptal edilebilir. İptal edilen relay'in iletimleri hemen reddedilir.

## Kurulum

1. Sunucuda relay sertifikası üretin:

   ```bash
   ber-server relay create -config ber-server.yaml -name "İzmir şubesi" -hostnames relay-izmir.ornek.local -out ./relay-izmir
   ```

   Klasörde `relay.crt`, `relay.key` ve `ca.crt` oluşur. `relay.key` gizlidir; yalnızca relay makinesine kopyalayın.

2. Klasörü relay makinesine kopyalayıp başlatın:

   ```bash
   ber-relay -server https://ber.ornek.local:52311 -dir ./relay-izmir -cache ./cache -cache-gb 100
   ```

3. Şubedeki ajanları kurarken sunucu adresi olarak relay'i verin (`https://relay-izmir.ornek.local:52311`). CA parmak izi merkezdeki ile aynıdır.

| Bayrak | Varsayılan | Açıklama |
|---|---|---|
| `-server` | — | Sunucunun ajan adresi |
| `-dir` | `.` | `relay.crt`, `relay.key`, `ca.crt` klasörü |
| `-listen` | `:52311` | Ajanların bağlanacağı adres |
| `-cache` | `cache` | Paket önbelleği klasörü |
| `-cache-gb` | `50` | Önbellek üst sınırı (GB) |

Relay durumsuzdur; önbellek silinse bile dosyalar ilk istekte yeniden indirilir.

Tasarım: [docs/mimari.md](../docs/mimari.md), ayrıntılar: [docs/gelismis-dagitim.md](../docs/gelismis-dagitim.md).
