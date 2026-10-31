# Tanıtım Sayfası

GitHub Pages'te yayımlanan statik tanıtım sayfası: <https://berkayatag.github.io/BerOps/>

- `index.html`, `landing.css`, `landing.js`, `init.js`: sayfa. Varsayılan aydınlık tema ve Türkçe; tema ve dil seçimi tarayıcıda hatırlanır.
- Renkler konsolla aynı `design/tokens.css` dosyasından gelir; yayında `tokens.css` olarak kopyalanır.
- `img/<ekran>-<tr|en>-<light|dark>.webp`: demo verilerle (sanal ajanlar) alınmış ekran görüntüleri. Sayfa seçilen dile ve temaya uygun görseli gösterir, tıklanınca büyütür.

Yerelde önizleme:

```bash
landing/build.sh /tmp/berops-landing && python3 -m http.server -d /tmp/berops-landing 8080
```

Yayın: `main` dalına `landing/` veya `design/` değişikliği gelince `.github/workflows/pages.yml` çalışır.
