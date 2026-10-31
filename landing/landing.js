// Tanıtım sayfası: dil (TR varsayılan, EN) ve tema düğmeleri. Türkçe metinler HTML'dedir;
// İngilizce seçildiğinde aşağıdaki sözlükten uygulanır ve tercih konsolla aynı anahtarla saklanır.
(function () {
  "use strict";

  var EN = {
    skip: "Skip to content",
    "nav.features": "Features",
    "nav.architecture": "Architecture",
    "nav.screens": "Screenshots",
    "nav.install": "Install",
    "nav.faq": "FAQ",
    "theme.toDark": "Switch to dark theme",
    "theme.toLight": "Switch to light theme",
    "hero.eyebrow": "Open source · Windows and macOS",
    "hero.title": "Manage patches, applications and vulnerabilities from one console",
    "hero.lead":
      "Automation BER collects missing patches, third-party applications and CVEs across your fleet with agents, prioritises them by risk and closes them with signed, bandwidth-limited, staged deployments.",
    "hero.download": "Download (GitHub Releases)",
    "hero.source": "Source code",
    "hero.b1": "mTLS + signed jobs",
    "hero.b2": "NVD · MSRC · KEV · EPSS",
    "hero.b3": "AD / LDAPS and RBAC",
    "features.title": "Features",
    "f1.t": "Inventory and missing patches",
    "f1.d": "Missing patches via Windows Update Agent and softwareupdate, patch level (build/UBR), installed KBs and third-party applications. Delta scans and a CPU limit.",
    "f2.t": "CVE engine and risk score",
    "f2.d": "Matching with NVD, MSRC, CISA KEV and EPSS data; a 0-100 risk score from CVSS, exploit probability and active exploitation.",
    "f3.t": "Patch and package deployment",
    "f3.d": "OS patches, a package library (MSI, EXE, PKG, DMG) and commands. Ed25519-signed jobs, SHA-256 verification and a per-client bandwidth limit.",
    "f4.t": "Staged rollouts and maintenance windows",
    "f4.d": "A pilot ring and stages; the rollout pauses automatically if the success rate drops below the threshold. Jobs run only inside the machine's maintenance window.",
    "f5.t": "Active Directory and RBAC",
    "f5.d": "LDAPS sign-in with roles and OU scope from nested groups. Administrator, Technician and Read-only roles; permissions are checked on the server for every API call.",
    "f6.t": "Opt-in remote management",
    "f6.d": "Live CPU, memory and disk; services and registry. Off by default, enabled per machine, and every operation is written to the audit log.",
    "f7.t": "Branch relays",
    "f7.d": "Branch agents connect through a relay; packages are downloaded once, verified and served from the local cache.",
    "f8.t": "Reports and notifications",
    "f8.d": "PDF, Excel and CSV reports with scheduled email. Teams, Slack and signed webhook notifications; an immutable audit log.",
    "arch.title": "Architecture",
    "arch.lead":
      "A single Go server serves the console and the agent API. Agents connect to the server (or to a branch relay) over mutual TLS; the server keeps its data in PostgreSQL.",
    "arch.console": "Console",
    "arch.ports": ":8443 console · :52311 agents",
    "arch.browser": "Browser · HTTPS",
    "arch.engine": "CVE engine · signed jobs",
    "arch.agents": "Agents (Windows, macOS)",
    "arch.relay": "Relay → branch agents",
    "shots.title": "Screenshots",
    "shots.lead": "Screenshots were taken with demo data (simulated agents).",
    "shots.patches": "Missing patches across the fleet and deployment",
    "shots.rollout": "Staged patch deployment and stage status",
    "shots.vulns": "Vulnerabilities sorted by risk",
    "shots.machine": "Machine detail: risk, inventory, patches",
    "shots.machines": "Machine list and filters",
    "shots.dark": "Dark theme",
    "shots.dashboard": "Dashboard: machine, missing patch and risk summaries",
    "shots.dashboardDark": "Dashboard (dark theme)",
    "install.title": "Install",
    "s1.t": "Install the server",
    "s1.d": "With the wizard-based MSI on Windows Server or with Docker Compose on Linux. PostgreSQL 15 or later is required.",
    "s2.t": "Create a registration key",
    "s2.d": "The console's \"Download agent\" page prepares install commands with the server address, registration key and CA fingerprint embedded.",
    "s3.t": "Deploy the agents",
    "s3.d": "A silent MSI for Windows (GPO, SCCM, Intune) and a .pkg for macOS (MDM).",
    "s4.t": "Close the risks",
    "s4.d": "Review missing patches and vulnerabilities, ship patches with maintenance windows and staged rollouts, and schedule reports.",
    "install.cta": "Download the latest release",
    "install.docs": "Installation guide",
    "req.title": "System requirements",
    "req.c1": "Component",
    "req.c2": "Supported",
    "req.c3": "Resources",
    "req.server": "Server",
    "req.serverRes": "Suggested start: 2 vCPU, 4 GB RAM; PostgreSQL 15+",
    "req.win": "Windows agent",
    "req.mac": "macOS agent",
    "req.agentRes": "Idle < 1% CPU, ~15-25 MB RAM",
    "req.console": "Console",
    "req.browsers": "Current Chrome, Edge, Firefox, Safari",
    "req.ports": "Network",
    "req.portsRes": "One-way connection from agent to server",
    "faq.title": "Frequently asked questions",
    q1: "In which direction does the agent connect?",
    a1: "Only from the agent to the server (or relay). No inbound ports are needed on agents; jobs are fetched by the agent's polling.",
    q2: "How is it ensured that jobs don't come from a fake server?",
    a2: "The agent pins the server's CA fingerprint and every job is signed with Ed25519. Downloaded files are verified with SHA-256; expired jobs or jobs for another machine are rejected.",
    q3: "Does it work in networks without internet access?",
    a3: "Yes. CVE data can be loaded from an offline folder and the Windows missing patch scan can use an offline wsusscn2.cab.",
    q4: "What can the Technician role do?",
    a4: "Only send ready-made packages from the library. Free-form commands, patch deployment and settings require an administrator; scope can be limited by OUs.",
    q5: "Is remote management on by default?",
    a5: "No. The global switch and per-machine features are off by default, and when enabled every operation is written to the audit log.",
    q6: "What is the license?",
    a6: "Apache License 2.0. You may use, modify and distribute it freely, including commercially.",
    "footer.by": "Developed by:",
    "footer.security": "Security",
  };

  var root = document.documentElement;
  var tr = {};
  var trAlt = {};
  var trAria = {};
  var title = { tr: document.title, en: "Automation BER — Agent-based patch and application management" };

  function each(attr, fn) {
    var nodes = document.querySelectorAll("[" + attr + "]");
    for (var i = 0; i < nodes.length; i++) fn(nodes[i], nodes[i].getAttribute(attr));
  }

  // Türkçe metinler ilk yüklemede saklanır; dil değişince geri yüklenir.
  each("data-i18n", function (el, k) {
    if (!(k in tr)) tr[k] = el.textContent;
  });
  each("data-i18n-alt", function (el, k) {
    trAlt[k] = el.getAttribute("alt");
  });
  each("data-i18n-aria", function (el, k) {
    trAria[k] = el.getAttribute("aria-label");
  });

  function store(key, value) {
    try {
      localStorage.setItem(key, value);
    } catch (e) {
      // Gizli modda tercih saklanamaz; sayfa yine çalışır.
    }
  }

  function setLang(lang) {
    var en = lang === "en";
    each("data-i18n", function (el, k) {
      el.textContent = en && EN[k] ? EN[k] : tr[k];
    });
    each("data-i18n-alt", function (el, k) {
      el.setAttribute("alt", en && EN[k] ? EN[k] : trAlt[k]);
    });
    root.lang = en ? "en" : "tr";
    document.title = en ? title.en : title.tr;
    var buttons = document.querySelectorAll("[data-lang]");
    for (var i = 0; i < buttons.length; i++) {
      buttons[i].setAttribute("aria-pressed", String(buttons[i].getAttribute("data-lang") === lang));
    }
    syncThemeLabel();
  }

  function syncThemeLabel() {
    var dark = root.getAttribute("data-theme") === "dark";
    var en = root.lang === "en";
    var label = dark ? (en ? EN["theme.toLight"] : "Açık temaya geç") : en ? EN["theme.toDark"] : trAria["theme.toDark"];
    document.getElementById("theme").setAttribute("aria-label", label);
  }

  document.getElementById("theme").addEventListener("click", function () {
    var next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
    root.setAttribute("data-theme", next);
    store("ber-theme", next);
    syncThemeLabel();
  });

  var langButtons = document.querySelectorAll("[data-lang]");
  for (var i = 0; i < langButtons.length; i++) {
    langButtons[i].addEventListener("click", function (e) {
      var lang = e.currentTarget.getAttribute("data-lang");
      store("ber-lang", lang);
      setLang(lang);
    });
  }

  var saved = null;
  try {
    saved = localStorage.getItem("ber-lang");
  } catch (e) {
    saved = null;
  }
  setLang(saved === "en" ? "en" : "tr");
})();
