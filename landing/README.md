# Tanıtım Sayfası

GitHub Pages'te yayımlanan statik tanıtım sayfası: <https://berkayatag.github.io/automation-ber/>

- `index.html`, `landing.css`, `landing.js`: sayfa (Türkçe varsayılan, İngilizce seçenekli; karanlık mod).
- Renkler konsolla aynı `design/tokens.css` dosyasından gelir; yayında `tokens.css` olarak kopyalanır.
- `img/`: demo verilerle (sanal ajanlar) alınmış ekran görüntüleri.

Yerelde önizleme:

```bash
landing/build.sh /tmp/ber-landing && python3 -m http.server -d /tmp/ber-landing 8080
```

Yayın: `main` dalına `landing/`, `design/` değişikliği gelince `.github/workflows/pages.yml` çalışır.
