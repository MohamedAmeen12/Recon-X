document.addEventListener("DOMContentLoaded", async () => {
  const params = new URLSearchParams(window.location.search);
  const domain = params.get("domain");
  const reportId = params.get("report_id");
  const domainTitle = document.getElementById("domain-title");
  const reportContent = document.getElementById("report-content");

  /* ===============================
     CHART REGISTRY (PREVENT OVERLAP)
  =============================== */
  const chartRegistry = {};

  /* ===============================
     VALIDATION
  =============================== */
  if (!domain && !reportId) {
    reportContent.innerHTML = "<p style='color:red;'>No report specified!</p>";
    return;
  }

  domainTitle.textContent = `Domain: ${domain}`;
  reportContent.innerHTML = "<p>Loading report…</p>";

  /* ===============================
     CHART HELPERS
  =============================== */
  function renderPie(canvasId, data) {
    if (!data || !Object.keys(data).length) return;
    const el = document.getElementById(canvasId);
    if (!el) return;

    if (chartRegistry[canvasId]) {
      chartRegistry[canvasId].destroy();
    }

    chartRegistry[canvasId] = new Chart(el, {
      type: "doughnut",
      data: {
        labels: Object.keys(data),
        datasets: [{
          data: Object.values(data),
          backgroundColor: [
            "#3b82f6",
            "#10b981",
            "#f59e0b",
            "#ef4444",
            "#8b5cf6",
            "#14b8a6"
          ],
          borderWidth: 0
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: "bottom" }
        }
      }
    });
  }

  function renderBar(canvasId, data) {
    if (!data || !Object.keys(data).length) return;
    const el = document.getElementById(canvasId);
    if (!el) return;

    if (chartRegistry[canvasId]) {
      chartRegistry[canvasId].destroy();
    }

    chartRegistry[canvasId] = new Chart(el, {
      type: "bar",
      data: {
        labels: Object.keys(data),
        datasets: [{
          data: Object.values(data),
          backgroundColor: "#3b82f6",
          borderRadius: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          y: { beginAtZero: true }
        }
      }
    });
  }

  /* ===============================
     FETCH REPORT
  =============================== */
  try {
    let fetchUrl = "";
    if (reportId) {
      fetchUrl = `http://localhost:5000/get_report?report_id=${encodeURIComponent(reportId)}`;
    } else {
      fetchUrl = `http://localhost:5000/get_report?domain=${encodeURIComponent(domain)}`;
    }

    const resp = await fetch(fetchUrl);
    if (resp.status === 401 || resp.status === 403) {
      reportContent.innerHTML = "<p style='color:red;'>Unauthorized. Please login to view this report.</p>";
      return;
    }
    if (!resp.ok) throw new Error("Failed to load report");

    const data = await resp.json();

    // ✅ FIX: Update domain title from backend data if URL param is missing
    if (data.domain) {
      domainTitle.textContent = `Domain: ${data.domain}`;
    }

    if (!data.result) {
      reportContent.innerHTML = "<p>No report data found.</p>";
      return;
    }

    const r = data.result;

    /* ===============================
       MODEL 1 – CLUSTERS
    =============================== */
    const portMap = {};
    r.raw_docs?.forEach(doc => {
      portMap[doc.subdomain] = doc.open_ports || [];
    });

    const clustersHTML = (r.clusters || []).map(c => {
      const items = (c.examples || []).map(sub => {
        const ports = portMap[sub] || [];
        const text = ports.length
          ? ports.map(p => `${p.port}/${p.service}`).join(", ")
          : "No open ports";
        return `
          <li>
            <strong>${sub}</strong>
            <span class="card-text">(${text})</span>
          </li>`;
      }).join("");

      return `
        <div class="cluster-block card">
          <h4>Cluster ${c.cluster_id} (${c.size})</h4>
          <ul>${items}</ul>
        </div>`;
    }).join("");

    const examplesHTML = (r.examples || []).map(e => `<li>${e}</li>`).join("");

    /* ===============================
       MODEL 2 – OPEN PORTS
    =============================== */
    const model2HTML = Object.keys(portMap).length ? `
      <h3>Open Ports & Services (Model 2)</h3>
      ${Object.entries(portMap).map(([sub, ports]) => `
        <div class="port-block card">
          <strong>${sub}</strong>
          ${ports.length
        ? `<ul>${ports.map(p =>
          `<li>${p.port}/${p.service}</li>`).join("")}</ul>`
        : `<p class="card-text">No open ports detected</p>`}
        </div>
      `).join("")}
    ` : "";

    /* ===============================
       MODEL 3 – TECHNOLOGIES
    =============================== */
    const model3HTML = r.technology_fingerprints?.length ? `
      <h3>Technology Fingerprints (Model 3)</h3>
      ${r.technology_fingerprints.map(t => `
        <div class="tech-box card">
          <h4>${t.url || "Unknown URL"}</h4>
          ${t.technologies.map(tech => `
            <div class="tech-item card-text" style="margin-bottom: 10px; padding-bottom: 5px; border-bottom: 1px solid rgba(255,255,255,0.1);">
              <strong>${tech.technology}</strong> ${tech.version || ""}
              <br>
              <small>Category: ${tech.category || "Unknown"} | Status: ${tech.vulnerability_status}</small>
              ${tech.cves && tech.cves.length ? `
                <div class="cve-list" style="margin-top: 5px; font-size: 0.85rem;">
                  <strong>Vulnerabilities:</strong>
                  <ul style="margin: 5px 0; padding-left: 20px;">
                    ${tech.cves.map(cve => {
      const isRealCVE = cve.cve && cve.cve.startsWith("CVE-");
      return `
                        <li>
                          ${isRealCVE ? `
                            <a href="https://nvd.nist.gov/vuln/detail/${cve.cve}" target="_blank" style="color: #38bdf8; text-decoration: underline;">
                              ${cve.cve}
                            </a>` : `
                            <span style="color: #f59e0b; font-weight: bold;">${cve.cve}</span>
                          `}
                          (CVSS: ${cve.cvss}) - ${cve.severity}
                        </li>`;
    }).join("")}
                  </ul>
                </div>
              ` : ""}
            </div>
          `).join("")}
        </div>
      `).join("")}
    ` : "";

    /* ===============================
       MODEL 4 – HTTP & TRAFFIC ANOMALIES
    =============================== */
    const model4HTML = r.http_anomalies?.length ? `
      <h3>HTTP & Traffic Anomaly Detection (Model 4)</h3>
      ${r.http_anomalies.map(a => {
      const res = a.model4_result || {};
      const signals = res.signals || [];
      const isAnom = res.status === 'suspicious';
      return `
        <div class="anomaly-row ${isAnom ? 'suspicious' : ''}">
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <strong>${a.subdomain}</strong>
            <span class="badge" style="background: ${isAnom ? '#ef4444' : '#10b981'}; color: white;">
              ${res.status?.toUpperCase() || "UNKNOWN"}
            </span>
          </div>
          
          <div class="card-text">
             ${res.traffic_data ? `
                <div class="traffic-snippet">
                  📡 <strong>Traffic Analysis:</strong> ${res.traffic_data.packet_count} packets detected | ${res.traffic_data.tcp_syn_count} SYNs | ${res.traffic_data.unique_ips} Unique IPs
                </div>
             ` : ""}
             
             <div class="signal-list">
               ${signals.length ? `
                 <strong>Audit Findings:</strong>
                 <ul>
                   ${signals.map(s => `<li>${s}</li>`).join("")}
                 </ul>
               ` : `<small style="color: #94a3b8 !important;">Factual Audit: No security violations identified.</small>`}
             </div>
          </div>
        </div>
      `;
    }).join("")}
    ` : "";

    /* ===============================
       MODEL 5 – STATISTICS (VERTICAL CHARTS)
    =============================== */
    let model5StatsHTML = "";
    if (r.model5?.statistics) {
      const s = r.model5.statistics;

      model5StatsHTML = `
        <h3>Exploitation Strategy – Statistics (Model 5)</h3>

        <div class="kpi-row">
          <div class="kpi card">Total Strategies<br>${r.model5.strategy_count}</div>
          <div class="kpi card">MITRE Techniques<br>${Object.keys(s.by_mitre || {}).length}</div>
          <div class="kpi card">Weaponized<br>${s.by_exploit_type?.weaponized || 0}</div>
        </div>

        <!-- 🔥 VERTICAL CHART STACK -->
        <div class="charts-vertical">
          <div class="chart-item"><canvas id="m5-source-chart"></canvas></div>
          <div class="chart-item"><canvas id="m5-confidence-chart"></canvas></div>
          <div class="chart-item"><canvas id="m5-mitre-chart"></canvas></div>
          <div class="chart-item"><canvas id="m5-port-chart"></canvas></div>
        </div>
      `;

      requestAnimationFrame(() => {
        renderPie("m5-source-chart", s.by_source);
        renderPie("m5-confidence-chart", s.by_confidence);
        renderBar("m5-mitre-chart", s.by_mitre);
        renderBar("m5-port-chart", s.by_port);
      });
    }

    /* ===============================
       MODEL 5 – STRATEGIES
    =============================== */
    const model5HTML = r.model5?.strategies?.length ? `
      <h3>Exploitation Strategies (Model 5)</h3>
      ${r.model5.strategies.map(s => `
        <div class="strategy-card card">
          <h4>${s.technology} ${s.version || ""}</h4>
          <p class="card-text">
            <strong>Attack Chain:</strong> ${s.attack_chain.join(" → ")}
          </p>
          ${s.confidence
        ? `<p class="card-text"><strong>Confidence:</strong> ${s.confidence}</p>`
        : ""}
        </div>
      `).join("")}
    ` : "";

    /* ===============================
       FINAL RENDER
    =============================== */
    reportContent.innerHTML = `
      <div class="summary card">
        <strong>Total Candidates:</strong> ${r.total_candidates || 0}
      </div>

      <h3>Clusters (Model 1)</h3>
      ${clustersHTML}

      <h3>Examples (Model 1)</h3>
      <ul>${examplesHTML}</ul>

      ${model2HTML}
      ${model3HTML}
      ${model4HTML}
      ${model5StatsHTML}
      ${model5HTML}
    `;

  } catch (err) {
    console.error(err);
    reportContent.innerHTML =
      `<p style="color:red;">Error loading report: ${err.message}</p>`;
  }
});
