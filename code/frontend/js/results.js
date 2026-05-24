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

function renderPipelineLog(log) {
  const panel = document.getElementById("pipeline-panel");
  const list = document.getElementById("pipeline-list");
  hide(panel);

  if (!log?.length) return;

  list.innerHTML = "";
  log.forEach((entry) => {
    const li = document.createElement("li");
    li.className = `pipeline-${entry.status || "ok"}`;
    const msg = entry.message ? ` — ${entry.message}` : "";
    li.textContent = `${entry.phase}: ${entry.status}${msg}`;
    list.appendChild(li);
  });
  show(panel);
}

function renderExploitation(exploitation) {
  const panel = document.getElementById("exploit-panel");
  const flagPanel = document.getElementById("flag-panel");
  const flagContent = document.getElementById("flag-content");
  const stepsBox = document.getElementById("exploit-steps");
  const reportBtn = document.getElementById("download-report-btn");

  hide(panel);
  hide(flagPanel);

  if (!exploitation?.attempts?.length) return;

  stepsBox.innerHTML = "";
  exploitation.attempts.forEach((attempt) => {
    const block = document.createElement("div");
    block.className = "exploit-block";
    const title = document.createElement("h3");
    title.textContent = `FTP ${attempt.host}:${attempt.port}`;
    block.appendChild(title);

    const ul = document.createElement("ul");
    (attempt.steps || []).forEach((step) => {
      const li = document.createElement("li");
      li.className = `step-${step.status || "ok"}`;
      li.textContent = `[${step.action}] ${step.detail}`;
      ul.appendChild(li);
    });
    block.appendChild(ul);

    if (attempt.error) {
      const err = document.createElement("p");
      err.className = "muted";
      err.textContent = `Error: ${attempt.error}`;
      block.appendChild(err);
    }

    stepsBox.appendChild(block);
  });

  show(panel);

  if (exploitation.flag_captured && exploitation.flags?.length) {
    flagContent.innerHTML = exploitation.flags
      .map(
        (f) =>
          `<p><strong>${escapeHtml(f.filename)}</strong></p><pre class="flag-pre">${escapeHtml(f.content)}</pre>`
      )
      .join("");
    show(flagPanel);
    const wordBtn = document.getElementById("download-report-btn");
    const htmlBtn = document.getElementById("download-report-html-btn");
    if (wordBtn) wordBtn.disabled = false;
    if (htmlBtn) htmlBtn.disabled = false;
  }
}

async function downloadAuditReport(format) {
  if (!window.lastScanData?.exploitation?.flag_captured) {
    alert("El informe solo está disponible cuando se ha capturado una flag.");
    return;
  }

  const isHtml = format === "html";
  const btn = document.getElementById(
    isHtml ? "download-report-html-btn" : "download-report-btn"
  );
  const defaultLabel = isHtml ? "Informe Linux (HTML)" : "Informe Word (.docx)";

  if (btn) {
    btn.disabled = true;
    btn.textContent = "Generando informe…";
  }

  try {
    const response = await fetch(`${API_BASE}/api/report`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        scan_data: window.lastScanData,
        format: isHtml ? "html" : "docx",
      }),
    });

    const contentType = response.headers.get("Content-Type") || "";
    if (!response.ok || contentType.includes("application/json")) {
      const err = await response.json();
      throw new Error(err.error || "No se pudo generar el informe");
    }

    const blob = await response.blob();
    const disposition = response.headers.get("Content-Disposition") || "";
    const match = disposition.match(/filename=\"?([^\";]+)\"?/);
    const fallback = isHtml ? "informe_pentest.html" : "informe_pentest.docx";
    const filename = match ? match[1] : fallback;

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();

    if (isHtml) {
      window.open(url, "_blank");
    }
    setTimeout(() => URL.revokeObjectURL(url), 3000);
  } catch (err) {
    alert(err.message || "Error al descargar el informe");
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = defaultLabel;
    }
  }
}

function renderAiAnalysis(ai) {
  const aiPanel = document.getElementById("ai-panel");
  const disabledPanel = document.getElementById("ai-disabled-panel");

  hide(aiPanel);
  hide(disabledPanel);

  if (!ai) return;

  if (!ai.enabled && !ai.analysis) {
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

  const provider = ai.provider || "?";
  const model = ai.model || "?";
  document.getElementById("ai-meta").textContent = `Fuente: ${provider} · Modelo: ${model}`;
  show(aiPanel);
}

async function runScan(target) {
  const status = document.getElementById("scan-status");
  status.textContent =
    "Escaneando (nmap → CVE → FTP/flag → IA). Puede tardar varios minutos…";
  status.className = "status scanning";

  const response = await fetch(`${API_BASE}/api/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      target,
      enrich_cve: true,
      ai_analyze: true,
      auto_exploit: true,
    }),
  });

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }

  return response.json();
}

function renderResults(data) {
  window.lastScanData = data;

  const status = document.getElementById("scan-status");
  const errorPanel = document.getElementById("error-panel");
  const warnPanel = document.getElementById("warn-panel");
  const osPanel = document.getElementById("os-panel");
  const portsPanel = document.getElementById("ports-panel");
  const emptyPanel = document.getElementById("empty-panel");

  hide(errorPanel);
  hide(warnPanel);
  hide(osPanel);
  hide(portsPanel);
  hide(emptyPanel);

  const hasResults = (data.results || []).length > 0;

  if (data.error && !hasResults) {
    errorPanel.textContent = data.error;
    show(errorPanel);
    status.textContent = "Error en el escaneo";
    status.className = "status";
    renderPipelineLog(data.pipeline_log);
    return;
  }

  if (data.error && hasResults) {
    warnPanel.textContent = `Aviso parcial: ${data.error}`;
    show(warnPanel);
  }

  if (data.warnings?.length) {
    warnPanel.textContent = data.warnings.join(" | ");
    show(warnPanel);
  }

  const cveCount = (data.results || []).reduce(
    (acc, row) => acc + (row.cve_findings?.length || 0),
    0
  );

  const flagText = data.exploitation?.flag_captured ? " · FLAG OK" : "";
  status.textContent = `Completado — ${data.results?.length ?? 0} puerto(s), ${cveCount} CVE(s)${flagText}`;
  status.className = "status done";

  renderPipelineLog(data.pipeline_log);
  renderExploitation(data.exploitation);

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

  if (!hasResults) {
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

  const reportBtn = document.getElementById("download-report-btn");
  if (reportBtn) reportBtn.addEventListener("click", () => downloadAuditReport("docx"));

  const reportHtmlBtn = document.getElementById("download-report-html-btn");
  if (reportHtmlBtn) reportHtmlBtn.addEventListener("click", () => downloadAuditReport("html"));

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
