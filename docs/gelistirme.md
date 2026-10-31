# Geliştirme ortamı

BerOps'u kaynak koddan çalıştırmak, ajan kaydetmek ve testleri koşmak için.

## Hızlı başlangıç

Gereksinimler: Go 1.27+, Node.js 24+, Docker.

PostgreSQL'i başlatın:

```bash
docker compose -f deploy/docker-compose.dev.yml up -d --wait
```

Sunucu yapılandırmasını oluşturun (`berops-server.yaml`, git'e eklenmez):

```yaml
data_dir: ./data
database_url: postgres://ber:ber@localhost:5432/ber_dev?sslmode=disable
```

İlk admin hesabını oluşturun ve sunucuyu başlatın:

```bash
go run ./server/cmd/berops-server admin create -username admin
```

```bash
go run ./server/cmd/berops-server serve
```

Konsolu geliştirme modunda açın (API istekleri `https://localhost:8443` adresine aktarılır):

```bash
npm --prefix console install && npm --prefix console run dev
```

Tarayıcıda `http://localhost:5173` adresine gidin.

## Ajanı kaydetmek

Kayıt anahtarı oluşturun; komut CA parmak izini de yazdırır:

```bash
go run ./server/cmd/berops-server regkey create -name "Geliştirme"
```

Ajanı kaydedip çalıştırın (yönetici yetkisi gerekmez, `-data-dir` ile yerel bir klasör kullanılır):

```bash
go run ./agent/cmd/berops-agent enroll -data-dir ./agent-data -server https://localhost:52311 -key <anahtar> -ca-hash <parmak-izi>
```

```bash
go run ./agent/cmd/berops-agent run -data-dir ./agent-data
```

## Envanteri yerelde denemek

Sunucuya göndermeden bu makinenin envanterini görmek için (`-full` eksik güncelleme taramasını da yapar):

```bash
go run ./agent/cmd/berops-agent inventory -full
```

## CVE verisini eşitlemek

Sunucu açıldıktan bir dakika sonra kaynakları kendisi eşitler. Hemen eşitlemek için:

```bash
go run ./server/cmd/berops-server cve sync
```

## Sanal ajanlar

Gerçek ajanla aynı zamanlayıcıyı kullanan, gerçekçi sahte envanter (eksik KB'ler, CVE'ler, güncel olmayan uygulamalar, AD OU'ları) gönderen sanal ajanlar:

```bash
go run ./agent/cmd/berops-agentsim -server https://localhost:52311 -key <anahtar> -ca-hash <parmak-izi> -n 100 -first-scan 30s
```

## Testler

Go testleri (PostgreSQL entegrasyon testleri `BER_TEST_DATABASE_URL` tanımlıysa çalışır):

```bash
BER_TEST_DATABASE_URL='postgres://ber:ber@localhost:5432/postgres?sslmode=disable' go test -race ./...
```

Konsol testleri:

```bash
npm --prefix console test -- --run
```
