function getTargetFromUrl() {
  const params = new URLSearchParams(window.location.search);
  return params.get("target")?.trim() || "";
}

function severityClass(severity) {
  if (!severity) return "badge-none";
  const s = String(severity).toLowerCase();
  if (s.includes("critical")) return "badge-critical";
  if (s.includes("high")) return "badge-high";
  return "badge-none";
}

function show(el) {
  el.classList.remove("hidden");
}

function hide(el) {
  el.classList.add("hidden");
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function renderCveCell(row) {
  const findings = row.cve_findings?.length
    ? row.cve_findings
    : row.vulnerability
      ? [{ ...row.vulnerability, source: "local" }]
      : [];

  if (!findings.length) {
    return '<span class="badge badge-none">—</span>';
  }

  return findings
    .map((item) => {
      if (item.error) {
        return `<div class="cve-line muted">${escapeHtml(item.error)}</div>`;
      }
      const cve = item.cve || "CVE?";
      const cvss = item.cvss != null ? ` · CVSS ${item.cvss}` : "";
      const src = item.source ? ` [${item.source}]` : "";
      return `
        <div class="cve-line">
          <span class="badge ${severityClass(item.severity)}">${escapeHtml(cve)}</span>
          <span class="muted">${escapeHtml(item.severity || "")}${cvss}${escapeHtml(src)}</span>
          <div class="muted small">${escapeHtml(item.description || "")}</div>
        </div>
      `;
    })
    .join("");
}

function renderAiAnalysis(ai) {
  const aiPanel = document.getElementById("ai-panel");
  const disabledPanel = document.getElementById("ai-disabled-panel");

  hide(aiPanel);
  hide(disabledPanel);

  if (!ai) return;

  if (!ai.enabled) {
    document.getElementById("ai-disabled-msg").textContent =
      ai.message || "IA no disponible. Revisa el archivo .env del backend.";
    show(disabledPanel);
    return;
  }

  const analysis = ai.analysis || {};
  document.getElementById("ai-summary").textContent = analysis.summary || "Sin resumen.";

  const vectorsBox = document.getElementById("ai-vectors");
  vectorsBox.innerHTML = "";

  (analysis.vectors || []).forEach((vector) => {
    const card = document.createElement("article");
    card.className = "vector-card";
    const checks = (vector.suggested_checks || [])
      .map((c) => `<li><code>${escapeHtml(c)}</code></li>`)
      .join("");
    const ports = (vector.related_ports || []).join(", ") || "—";

    card.innerHTML = `
      <header>
        <h3>${escapeHtml(vector.title || "Vector")}</h3>
        <span class="badge ${severityClass(vector.priority)}">${escapeHtml(vector.priority || "medium")}</span>
      </header>
      <p>${escapeHtml(vector.rationale || "")}</p>
      <p class="muted small">Puertos relacionados: ${escapeHtml(ports)}</p>
      <ul>${checks}</ul>
    `;
    vectorsBox.appendChild(card);
  });

  const stepsList = document.getElementById("ai-next-steps");
  stepsList.innerHTML = "";
  (analysis.next_steps || []).forEach((step) => {
    const li = document.createElement("li");
    li.textContent = step;
    stepsList.appendChild(li);
  });

  document.getElementById("ai-meta").textContent = `Proveedor: ${ai.provider || "?"} · Modelo: ${ai.model || "?"}`;
  show(aiPanel);
}

async function runScan(target) {
  const status = document.getElementById("scan-status");
  status.textContent =
    "Escaneando con nmap, consultando NVD y generando vectores IA (puede tardar varios minutos)…";
  status.className = "status scanning";

  const response = await fetch(`${API_BASE}/api/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      target,
      enrich_cve: true,
      ai_analyze: true,
    }),
  });

  return response.json();
}

function renderResults(data) {
  const status = document.getElementById("scan-status");
  const errorPanel = document.getElementById("error-panel");
  const osPanel = document.getElementById("os-panel");
  const portsPanel = document.getElementById("ports-panel");
  const emptyPanel = document.getElementById("empty-panel");

  hide(errorPanel);
  hide(osPanel);
  hide(portsPanel);
  hide(emptyPanel);

  if (data.error) {
    errorPanel.textContent = data.error;
    show(errorPanel);
    status.textContent = "Error en el escaneo";
    status.className = "status";
    return;
  }

  const cveCount = (data.results || []).reduce(
    (acc, row) => acc + (row.cve_findings?.length || 0),
    0
  );

  status.textContent = `Completado — ${data.results?.length ?? 0} puerto(s), ${cveCount} hallazgo(s) CVE`;
  status.className = "status done";

  if (data.os?.length) {
    const osList = document.getElementById("os-list");
    osList.innerHTML = "";
    data.os.forEach((entry) => {
      const li = document.createElement("li");
      li.textContent = `${entry.name} (precisión ${entry.accuracy}%)`;
      osList.appendChild(li);
    });
    show(osPanel);
  }

  if (!data.results?.length) {
    show(emptyPanel);
    renderAiAnalysis(data.ai_analysis);
    return;
  }

  const tbody = document.getElementById("ports-body");
  tbody.innerHTML = "";

  data.results.forEach((row) => {
    const tr = document.createElement("tr");
    const productVersion = [row.product, row.version].filter(Boolean).join(" ") || "—";

    tr.innerHTML = `
      <td>${row.port}</td>
      <td>${row.state}</td>
      <td>${row.service}</td>
      <td>${escapeHtml(productVersion)}</td>
      <td>${escapeHtml(row.extra_info || "—")}</td>
      <td>${renderCveCell(row)}</td>
    `;
    tbody.appendChild(tr);
  });

  show(portsPanel);
  renderAiAnalysis(data.ai_analysis);
}

function init() {
  const target = getTargetFromUrl();
  const title = document.getElementById("target-title");

  if (!target) {
    window.location.href = "/";
    return;
  }

  title.textContent = target;
  document.title = `ReconTool — ${target}`;

  const miniForm = document.getElementById("mini-search");
  const miniInput = document.getElementById("mini-target");
  miniInput.value = target;

  miniForm.addEventListener("submit", (event) => {
    event.preventDefault();
    const next = miniInput.value.trim();
    if (!next) return;
    const url = new URL("/results.html", window.location.origin);
    url.searchParams.set("target", next);
    window.location.href = url.toString();
  });

  runScan(target)
    .then(renderResults)
    .catch((err) => {
      const errorPanel = document.getElementById("error-panel");
      errorPanel.textContent = err.message || "No se pudo contactar con la API";
      show(errorPanel);
      document.getElementById("scan-status").textContent = "Error de conexión";
    });
}

init();
