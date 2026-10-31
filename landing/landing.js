// Tanıtım sayfası: dil (TR varsayılan, EN), tema ve büyük görüntüleme.
// Türkçe metinler HTML'dedir; İngilizce seçilince aşağıdaki sözlük uygulanır.
// Ekran görüntüleri dile ve temaya göre img/<ad>-<dil>-<tema>.webp dosyasından gelir.
(function () {
  "use strict";

  var EN = {
    skip: "Skip to content",
    "nav.label": "Main menu",
    "nav.features": "Features",
    "nav.screens": "Screens",
    "nav.architecture": "Architecture",
    "nav.install": "Install",
    "hero.eyebrow": "Version 1.0 · Windows and macOS",
    "hero.t1": "Patches, vulnerabilities, apps.",
    "hero.t2": "One console.",
    "hero.lead": "Agents collect missing patches and CVEs; you prioritise by risk and close them with signed, staged deployments.",
    "hero.download": "Download server installer",
    "hero.docs": "Read the docs →",
    "hero.f1": "Windows and macOS agents",
    "hero.f2": "Staged rollouts",
    "hero.f3": "Light and dark theme",
    "hero.caption": "Real application screen · demo data",
    "features.eyebrow": "From detection to deployment",
    "features.t1": "Find the missing patch.",
    "features.t2": "Close it under control.",
    "f1.n": "01 / Inventory",
    "f1.t": "Missing patches and apps",
    "f1.d": "Windows Update and softwareupdate scans, patch level, installed applications.",
    "f2.n": "02 / Risk",
    "f2.t": "CVE engine",
    "f2.d": "Matching with NVD, MSRC, KEV and EPSS; a 0-100 risk score.",
    "f3.n": "03 / Deploy",
    "f3.t": "Patches, packages, commands",
    "f3.d": "Signed jobs, SHA-256 verification, per-client bandwidth limit.",
    "f4.n": "04 / Control",
    "f4.t": "Staged and windowed",
    "f4.d": "Pilot ring, success threshold and maintenance windows; stops on trouble.",
    "f5.n": "05 / Access",
    "f5.t": "Active Directory and roles",
    "f5.d": "LDAPS sign-in, OU scope; Administrator, Technician, Read-only.",
    "f6.n": "06 / Scale",
    "f6.t": "Relays and notifications",
    "f6.d": "Branch cache, Teams/Slack/email, scheduled reports.",
    "screens.eyebrow": "Screens",
    "screens.t1": "Light by default.",
    "screens.t2": "Dark is one click away.",
    "screens.lead": "Screenshots follow the theme and language you pick. Click to enlarge.",
    "shots.open": "Enlarge screenshot",
    "shots.dashboard": "Dashboard",
    "shots.patches": "Patches · missing updates across the fleet",
    "shots.rollout": "Staged patch deployment · stage status",
    "shots.vulns": "Vulnerabilities · sorted by risk",
    "shots.machine": "Machine detail · risk, inventory, patches",
    "arch.eyebrow": "Architecture",
    "arch.t1": "One server.",
    "arch.t2": "Every connection verified.",
    "arch.c1": "Endpoint",
    "arch.agent": "BerOps agent",
    "arch.agentD": "Inventory · Patch install · Signature check",
    "arch.c2": "Your server",
    "arch.serverD": "Console · Agent API · CVE engine",
    "arch.relay": "Relay",
    "arch.c3": "Operator",
    "arch.console": "Web console",
    "arch.consoleD": "Local account / AD · Approval · Reports",
    "arch.note": "Agents only connect outbound; no ports are opened on clients. GitHub Pages only serves this page.",
    "install.eyebrow": "Download and install",
    "install.t1": "Next, Install, Finish.",
    "install.t2": "Agents from the console.",
    "s1.t": "Download",
    "s1.d": "Run BerOps-Server-x64.msi on Windows Server (Docker Compose for Linux).",
    "s2.t": "Next",
    "s2.d": "PostgreSQL address, server name and the first administrator.",
    "s3.t": "Install",
    "s3.d": "Service, certificates, firewall and database are prepared.",
    "s4.t": "Finish",
    "s4.d": "Copy the install command from the console's \"Download agent\" page.",
    "install.notes": "All files and SHA256 →",
    "install.note": "Packages are unsigned; Programs and Features shows publisher Berkay Atağ. PostgreSQL 15+ is required.",
    "footer.security": "Security",
    "footer.changes": "Release history",
    "lb.close": "Close",
    "lb.prev": "Previous",
    "lb.next": "Next",
    "lb.label": "Screenshot",
    "theme.toDark": "Switch to dark theme",
    "theme.toLight": "Switch to light theme",
  };
  var TR_THEME = { toDark: "Karanlık temaya geç", toLight: "Aydınlık temaya geç" };
  var TITLE = { tr: document.title, en: "BerOps — Patch management, one console" };

  var root = document.documentElement;
  var tr = {};
  var trAttr = {};

  function all(sel) {
    return Array.prototype.slice.call(document.querySelectorAll(sel));
  }

  // Türkçe metinler ilk yüklemede saklanır; dil değişince geri yüklenir.
  all("[data-i18n]").forEach(function (el) {
    var k = el.getAttribute("data-i18n");
    if (!(k in tr)) tr[k] = el.textContent;
  });
  all("[data-i18n-alt]").forEach(function (el) {
    var k = el.getAttribute("data-i18n-alt");
    trAttr["alt:" + k] = tr[k] || el.getAttribute("alt");
  });
  all("[data-i18n-aria]").forEach(function (el) {
    var k = el.getAttribute("data-i18n-aria");
    trAttr["aria:" + k] = el.getAttribute("aria-label") || "Ekran görüntüsünü büyüt";
  });

  function lang() {
    return root.getAttribute("lang") === "en" ? "en" : "tr";
  }
  function theme() {
    return root.getAttribute("data-theme") === "dark" ? "dark" : "light";
  }
  function text(k, fallback) {
    return lang() === "en" && EN[k] ? EN[k] : fallback;
  }
  function shotSrc(name) {
    return "img/" + name + "-" + lang() + "-" + theme() + ".webp";
  }
  function store(key, value) {
    try {
      localStorage.setItem(key, value);
    } catch (e) {
      // Gizli modda tercih saklanamaz; sayfa yine çalışır.
    }
  }

  // Dil, tema veya ikisi değişince bütün metin ve görselleri yeniden uygular.
  function render() {
    all("[data-i18n]").forEach(function (el) {
      var k = el.getAttribute("data-i18n");
      el.textContent = text(k, tr[k]);
    });
    all("[data-i18n-alt]").forEach(function (el) {
      var k = el.getAttribute("data-i18n-alt");
      el.setAttribute("alt", text(k, trAttr["alt:" + k]));
    });
    all("[data-i18n-aria]").forEach(function (el) {
      var k = el.getAttribute("data-i18n-aria");
      el.setAttribute("aria-label", text(k, trAttr["aria:" + k]));
    });
    all("[data-shot]").forEach(function (btn) {
      var img = btn.querySelector("img");
      var src = shotSrc(btn.getAttribute("data-shot"));
      if (img.getAttribute("src") !== src) img.setAttribute("src", src);
    });
    all("[data-lang]").forEach(function (b) {
      b.setAttribute("aria-pressed", String(b.getAttribute("data-lang") === lang()));
    });
    var dark = theme() === "dark";
    var toggle = document.getElementById("theme-toggle");
    var label = dark ? text("theme.toLight", TR_THEME.toLight) : text("theme.toDark", TR_THEME.toDark);
    toggle.setAttribute("aria-pressed", String(dark));
    toggle.setAttribute("aria-label", label);
    toggle.setAttribute("title", label);
    document.title = TITLE[lang()];
    lightbox.setAttribute("aria-label", text("lb.label", "Ekran görüntüsü"));
    if (lightbox.open) showShot(current);
  }

  document.getElementById("theme-toggle").addEventListener("click", function () {
    var next = theme() === "dark" ? "light" : "dark";
    root.setAttribute("data-theme", next);
    store("berops.site.theme", next);
    render();
  });
  all("[data-lang]").forEach(function (b) {
    b.addEventListener("click", function () {
      var next = b.getAttribute("data-lang");
      root.setAttribute("lang", next);
      store("berops.site.lang", next);
      render();
    });
  });

  // Büyük görüntüleme.
  var lightbox = document.getElementById("lightbox");
  var lbImg = lightbox.querySelector("img");
  var lbCap = lightbox.querySelector("figcaption");
  var shots = all("[data-shot]");
  var current = 0;

  function showShot(i) {
    current = (i + shots.length) % shots.length;
    var btn = shots[current];
    var img = btn.querySelector("img");
    lbImg.setAttribute("src", shotSrc(btn.getAttribute("data-shot")));
    lbImg.setAttribute("alt", img.getAttribute("alt"));
    var cap = btn.parentNode.querySelector("figcaption");
    lbCap.textContent = cap ? cap.textContent : img.getAttribute("alt");
  }

  shots.forEach(function (btn, i) {
    btn.addEventListener("click", function () {
      showShot(i);
      if (typeof lightbox.showModal === "function") lightbox.showModal();
      else lightbox.setAttribute("open", "");
    });
  });
  lightbox.querySelector(".lb-close").addEventListener("click", function () {
    lightbox.close();
  });
  lightbox.querySelector(".lb-prev").addEventListener("click", function () {
    showShot(current - 1);
  });
  lightbox.querySelector(".lb-next").addEventListener("click", function () {
    showShot(current + 1);
  });
  // Görselin dışına (koyu alana) tıklanınca kapanır.
  lightbox.addEventListener("click", function (e) {
    if (e.target === lightbox) lightbox.close();
  });
  lightbox.addEventListener("keydown", function (e) {
    if (e.key === "ArrowLeft") showShot(current - 1);
    if (e.key === "ArrowRight") showShot(current + 1);
  });

  render();
})();
