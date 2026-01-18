document.addEventListener("DOMContentLoaded", async () => {
  const params = new URLSearchParams(window.location.search);
  const domain = params.get("domain");
  const domainTitle = document.getElementById("domain-title");
  const reportContent = document.getElementById("report-content");

  if (!domain) {
    reportContent.innerHTML = "<p style='color:red;'>No domain specified!</p>";
    return;
  }

  domainTitle.textContent = `Domain: ${domain}`;

  // ===============================
  // MODEL 5 – CHART HELPERS (GLOBAL)
  // ===============================
  function renderPie(canvasId, data) {
    if (!data || Object.keys(data).length === 0) return;
    const el = document.getElementById(canvasId);
    if (!el) return;

    new Chart(el, {
      type: "doughnut",
      data: {
        labels: Object.keys(data),
        datasets: [{ data: Object.values(data) }]
      },
      options: {
        responsive: true,
        plugins: { legend: { position: "bottom" } }
      }
    });
  }

  function renderBar(canvasId, data) {
    if (!data || Object.keys(data).length === 0) return;
    const el = document.getElementById(canvasId);
    if (!el) return;

    new Chart(el, {
      type: "bar",
      data: {
        labels: Object.keys(data),
        datasets: [{ data: Object.values(data) }]
      },
      options: {
        responsive: true,
        plugins: { legend: { display: false } }
      }
    });
  }

  try {
    const resp = await fetch(`http://localhost:5000/get_report?domain=${encodeURIComponent(domain)}`);
    if (!resp.ok) throw new Error("Failed to load report");
    const data = await resp.json();

    if (!data.result) {
      reportContent.innerHTML = "<p>No report data found for this domain.</p>";
      return;
    }

    const r = data.result;

    // ====================================================
    // MODEL 1 DATA (UNCHANGED)
    // ====================================================
    const portMap = {};
    if (r.raw_docs) {
      r.raw_docs.forEach(doc => {
        portMap[doc.subdomain] = doc.open_ports || [];
      });
    }

    const clustersHTML = (r.clusters || []).map(c => {
      const ex = (c.examples || []).map(sub => {
        const ports = portMap[sub] || [];
        const portsText = ports.length
          ? ports.map(p => `${p.port}/${p.service}`).join(", ")
          : "No open ports";

        return `<li><strong>${sub}</strong>
          <span style="color:#3b82f6; margin-left:8px;">(${portsText})</span>
        </li>`;
      }).join("");

      return `<div class="cluster-block">
        <h4>Cluster ${c.cluster_id} (${c.size} items)</h4>
        <ul>${ex}</ul>
      </div>`;
    }).join("");

    const examplesHTML = (r.examples || []).map(e => `<li>${e}</li>`).join("");

    // ====================================================
    // MODEL 2
    // ====================================================
    let model2HTML = "";
    if (Object.keys(portMap).length > 0) {
      model2HTML = `<h3>Open Ports & Services (Model 2)</h3>` +
        Object.entries(portMap).map(([sub, ports]) => `
          <div class="port-block">
            <strong>${sub}</strong>
            ${ports.length
              ? `<ul>${ports.map(p => `<li>${p.port}/${p.service}</li>`).join("")}</ul>`
              : "<p>No open ports detected</p>"}
          </div>
        `).join("");
    }

    // ====================================================
    // MODEL 3
    // ====================================================
    let technologiesHTML = "";
    if (r.technology_fingerprints?.length) {
      technologiesHTML = r.technology_fingerprints.map(t => `
        <div class="tech-box">
          <h4>${t.url || "N/A"}</h4>
          ${t.technologies.map(tech => `
            <div class="tech-item">
              <strong>${tech.technology}</strong> ${tech.version || ""}
              <br><small>Status: ${tech.vulnerability_status}</small>
            </div>
          `).join("")}
        </div>
      `).join("");
    }

    // ====================================================
    // MODEL 4
    // ====================================================
    let model4HTML = "";
    if (r.http_anomalies?.length) {
      model4HTML = `<h3>HTTP Anomaly Detection (Model 4)</h3>` +
        r.http_anomalies.map(a => `
          <div class="anomaly-row">
            <strong>${a.subdomain}</strong><br>
            Status: ${a.model4_result?.status || "UNKNOWN"}
          </div>
        `).join("");
    }

    // ====================================================
    // MODEL 5 – STATISTICS (NEW)
    // ====================================================
    let model5StatsHTML = "";
    if (r.model5?.statistics) {
      const s = r.model5.statistics;

      model5StatsHTML = `
        <h3>Exploitation Strategy – Statistics (Model 5)</h3>
        <div class="kpi-row">
          <div class="kpi">Total Strategies<br>${r.model5.strategy_count}</div>
          <div class="kpi">MITRE Techniques<br>${Object.keys(s.by_mitre || {}).length}</div>
          <div class="kpi">Weaponized<br>${s.by_exploit_type?.weaponized || 0}</div>
        </div>
        <div class="charts-grid">
          <canvas id="m5-source-chart"></canvas>
          <canvas id="m5-confidence-chart"></canvas>
          <canvas id="m5-mitre-chart"></canvas>
          <canvas id="m5-port-chart"></canvas>
        </div>
      `;

      requestAnimationFrame(() => {
        renderPie("m5-source-chart", s.by_source);
        renderPie("m5-confidence-chart", s.by_confidence);
        renderBar("m5-mitre-chart", s.by_mitre);
        renderBar("m5-port-chart", s.by_port);
      });
    }

    // ====================================================
    // MODEL 5 – RAW STRATEGIES (UNCHANGED)
    // ====================================================
    let model5HTML = "";
    if (r.model5?.strategies?.length) {
      model5HTML = `<h3>Exploitation Strategies (Model 5)</h3>` +
        r.model5.strategies.map(s => `
          <div class="strategy-card">
            <h4>${s.technology} ${s.version || ""}</h4>
            <p>${s.attack_chain.join(" → ")}</p>
          </div>
        `).join("");
    }

    // ====================================================
    // FINAL RENDER
    // ====================================================
    reportContent.innerHTML = `
      <div class="summary">
        <p><strong>Total Candidates:</strong> ${r.total_candidates || 0}</p>
      </div>

      <h3>Clusters (Model 1)</h3>
      ${clustersHTML}

      <h3>Examples (Model 1)</h3>
      <ul>${examplesHTML}</ul>

      ${model2HTML}
      ${technologiesHTML}
      ${model4HTML}

      ${model5StatsHTML}
      ${model5HTML}
    `;

  } catch (err) {
    console.error(err);
    reportContent.innerHTML = `<p style='color:red;'>Error loading report: ${err.message}</p>`;
  }
});
