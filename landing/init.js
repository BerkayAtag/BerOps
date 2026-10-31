// Sayfa boyanmadan önce kayıtlı tema ve dili uygular (yanıp sönme olmasın).
// Varsayılan aydınlık tema ve Türkçe; seçim bu tarayıcıda hatırlanır.
(function () {
  var root = document.documentElement;
  var theme = "light";
  var lang = "tr";
  try {
    if (localStorage.getItem("berops.site.theme") === "dark") theme = "dark";
    if (localStorage.getItem("berops.site.lang") === "en") lang = "en";
  } catch (e) {
    // Depolama erişilemiyorsa varsayılanlar kullanılır.
  }
  root.setAttribute("data-theme", theme);
  root.setAttribute("lang", lang);
})();
