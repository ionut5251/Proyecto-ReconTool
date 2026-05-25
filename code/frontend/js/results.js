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
  if (el) el.classList.remove("hidden");
}

function hide(el) {
  if (el) el.classList.add("hidden");
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

function formatAiMeta(ai, prefix = "Fuente") {
  if (!ai) return "";
  const provider = ai.provider || "playbook";
  if (provider === "playbook" || provider === "ollama") {
    return `${prefix}: ${provider}`;
  }
  if (ai.model) {
    return `${prefix}: ${provider} · Modelo: ${ai.model}`;
  }
  return `${prefix}: ${provider}`;
}

function renderAiVectors(containerId, analysis) {
  const vectorsBox = document.getElementById(containerId);
  if (!vectorsBox) return;
  vectorsBox.innerHTML = "";

  (analysis?.vectors || []).forEach((vector) => {
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
}

function renderAiPanel(ai, options = {}) {
  const panelId = options.panelId || "ai-panel";
  const summaryId = options.summaryId || "ai-summary";
  const vectorsId = options.vectorsId || "ai-vectors";
  const metaId = options.metaId || "ai-meta";

  const panel = document.getElementById(panelId);
  hide(panel);
  if (!ai?.analysis) return;

  document.getElementById(summaryId).textContent = ai.analysis.summary || "Sin resumen.";
  renderAiVectors(vectorsId, ai.analysis);
  document.getElementById(metaId).textContent = formatAiMeta(ai);
  show(panel);
}

function renderOsint(osint) {
  const panel = document.getElementById("osint-panel");
  const content = document.getElementById("osint-content");
  hide(panel);
  if (!osint) return;

  const parts = [];
  if (osint.hostname) {
    parts.push(`<p><strong>Hostname (reverse DNS):</strong> ${escapeHtml(osint.hostname)}</p>`);
  }
  if (osint.web?.length) {
    parts.push("<p><strong>Servicios web detectados:</strong></p><ul>");
    osint.web.forEach((w) => {
      const title = w.title ? ` — ${escapeHtml(w.title)}` : "";
      const err = w.error ? ` <span class="muted">(${escapeHtml(w.error)})</span>` : "";
      parts.push(
        `<li><code>${escapeHtml(w.url)}</code> → HTTP ${w.status ?? "?"}${title}${err}</li>`
      );
    });
    parts.push("</ul>");
  }
  if (osint.subdomains?.length) {
    parts.push("<p><strong>Hosts / subdominios:</strong></p><ul>");
    osint.subdomains.forEach((s) => parts.push(`<li><code>${escapeHtml(s)}</code></li>`));
    parts.push("</ul>");
  }
  if (osint.notes?.length) {
    parts.push('<p class="muted small">' + osint.notes.map(escapeHtml).join("<br>") + "</p>");
  }

  if (!parts.length) return;
  content.innerHTML = parts.join("");
  show(panel);
}

function renderAttackPlan(plan) {
  const panel = document.getElementById("attack-plan-panel");
  const msg = document.getElementById("attack-plan-msg");
  const list = document.getElementById("attack-plan-list");
  const cta = document.getElementById("attack-cta-panel");
  const btn = document.getElementById("proceed-attack-btn");

  hide(panel);
  hide(cta);

  if (!plan) return;

  msg.textContent = plan.message || "";
  list.innerHTML = "";

  (plan.vectors || []).forEach((v) => {
    const li = document.createElement("li");
    li.textContent = `${v.title} — ${v.summary || ""}`;
    if (plan.primary?.id === v.id) {
      li.className = "plan-primary";
    }
    list.appendChild(li);
  });

  show(panel);

  if (plan.primary?.id) {
    btn.disabled = false;
    btn.textContent = `Proceder con ataque: ${plan.primary.title}`;
    show(cta);
  } else {
    btn.disabled = true;
    btn.textContent = "Sin vector automático para este objetivo";
    show(cta);
  }
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

function exploitBlockTitle(attempt) {
  const mod = attempt.module || "";
  if (mod === "telnet_root_blank") {
    return `Telnet ${attempt.host}:${attempt.port}`;
  }
  return `FTP ${attempt.host}:${attempt.port}`;
}

function renderExploitation(exploitation) {
  const panel = document.getElementById("exploit-panel");
  const flagPanel = document.getElementById("flag-panel");
  const flagContent = document.getElementById("flag-content");
  const stepsBox = document.getElementById("exploit-steps");

  hide(panel);
  hide(flagPanel);

  if (!exploitation?.attempts?.length) return;

  stepsBox.innerHTML = "";
  exploitation.attempts.forEach((attempt) => {
    const block = document.createElement("div");
    block.className = "exploit-block";
    const title = document.createElement("h4");
    title.textContent = exploitBlockTitle(attempt);
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

async function runPassiveScan(target) {
  const status = document.getElementById("scan-status");
  status.textContent = "Recon pasivo (nmap → CVE → OSINT)…";
  status.className = "status scanning";

  const response = await fetch(`${API_BASE}/api/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      target,
      enrich_cve: true,
      osint: true,
      full_pipeline: false,
    }),
  });

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }

  return response.json();
}

async function runActiveAttack(scanData) {
  const status = document.getElementById("scan-status");
  status.textContent = "Ataque activo en curso…";
  status.className = "status scanning";

  const btn = document.getElementById("proceed-attack-btn");
  if (btn) {
    btn.disabled = true;
    btn.textContent = "Atacando…";
  }

  const response = await fetch(`${API_BASE}/api/attack`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      scan_data: scanData,
      ai_analyze: true,
    }),
  });

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }

  return response.json();
}

function renderPortsTable(data) {
  const osPanel = document.getElementById("os-panel");
  const portsPanel = document.getElementById("ports-panel");
  const emptyPanel = document.getElementById("empty-panel");
  const hasResults = (data.results || []).length > 0;

  hide(osPanel);
  hide(portsPanel);
  hide(emptyPanel);

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
}

function renderPassiveResults(data) {
  window.lastScanData = data;
  window.passiveScanData = data;

  const status = document.getElementById("scan-status");
  const errorPanel = document.getElementById("error-panel");
  const warnPanel = document.getElementById("warn-panel");

  hide(errorPanel);
  hide(warnPanel);

  const hasResults = (data.results || []).length > 0;

  if (data.error && !hasResults) {
    errorPanel.textContent = data.error;
    show(errorPanel);
    status.textContent = "Error en recon pasivo";
    status.className = "status";
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

  const webUrls = (data.osint?.web || [])
    .filter((w) => w.url && w.status)
    .map((w) => w.url);
  const urlHint = webUrls.length ? ` · ${webUrls.join(", ")}` : "";
  status.textContent = `Recon pasivo completado — ${data.results?.length ?? 0} puerto(s), ${cveCount} CVE(s)${urlHint}`;
  status.className = "status done";

  renderOsint(data.osint);
  renderPortsTable(data);
  renderAttackPlan(data.attack_plan);

  renderAiPanel(data.ai_analysis, {
    panelId: "passive-ai-panel",
    summaryId: "passive-ai-summary",
    vectorsId: "passive-ai-vectors",
    metaId: "passive-ai-meta",
  });
}

function renderActiveResults(data) {
  window.lastScanData = data;

  show(document.getElementById("phase-active"));

  const status = document.getElementById("scan-status");
  const flagText = data.exploitation?.flag_captured ? " · FLAG capturada" : "";
  status.textContent = `Ataque activo completado${flagText}`;
  status.className = data.exploitation?.flag_captured ? "status done flag-ok" : "status done";

  renderPipelineLog(data.pipeline_log);
  renderExploitation(data.exploitation);
  renderAiPanel(data.ai_analysis);

  const btn = document.getElementById("proceed-attack-btn");
  if (btn) {
    btn.disabled = true;
    btn.textContent = data.exploitation?.flag_captured
      ? "Ataque completado — flag obtenida"
      : "Ataque ejecutado";
  }
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
  if (reportBtn) {
    reportBtn.disabled = true;
    reportBtn.addEventListener("click", () => downloadAuditReport("docx"));
  }

  const reportHtmlBtn = document.getElementById("download-report-html-btn");
  if (reportHtmlBtn) {
    reportHtmlBtn.disabled = true;
    reportHtmlBtn.addEventListener("click", () => downloadAuditReport("html"));
  }

  const attackBtn = document.getElementById("proceed-attack-btn");
  attackBtn.addEventListener("click", async () => {
    if (!window.passiveScanData) return;
    try {
      const result = await runActiveAttack(window.passiveScanData);
      if (result.error && !result.exploitation) {
        throw new Error(result.error);
      }
      renderActiveResults(result);
    } catch (err) {
      alert(err.message || "Error en ataque activo");
      attackBtn.disabled = false;
      attackBtn.textContent = "Reintentar ataque activo";
    }
  });

  runPassiveScan(target)
    .then(renderPassiveResults)
    .catch((err) => {
      const errorPanel = document.getElementById("error-panel");
      errorPanel.textContent = err.message || "No se pudo contactar con la API";
      show(errorPanel);
      document.getElementById("scan-status").textContent = "Error de conexión";
    });
}

init();
