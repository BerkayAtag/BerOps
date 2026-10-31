// Sayfa çizilmeden önce temayı uygular (beyaz/karanlık yanıp sönmeyi önler).
// Kayıtlı tercih yoksa işletim sisteminin tercihi kullanılır. CSP satır içi betiğe izin
// vermediği için ayrı dosyadır.
(function () {
  var theme = "light";
  try {
    var saved = localStorage.getItem("ber-theme");
    if (saved === "light" || saved === "dark") {
      theme = saved;
    } else if (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) {
      theme = "dark";
    }
  } catch (e) {
    // localStorage erişilemiyorsa (gizli mod vb.) açık tema kullanılır.
  }
  document.documentElement.setAttribute("data-theme", theme);
})();
