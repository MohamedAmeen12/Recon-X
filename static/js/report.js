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
      <h3>Open Ports & Services</h3>
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
      <h3>Technology Fingerprints</h3>
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
      <h3>HTTP & Traffic Anomaly Detection</h3>
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
        <h3>Exploitation Strategy – Statistics</h3>

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
    /* ===============================
       MODEL 5 – STRATEGIES
    =============================== */
    // Use the raw strategies directly (backend cleans them up now)
    const rawStrategies = r.model5?.strategies || [];

    // Feature: Deduplication is still useful for display
    const uniqueStrategies = [];
    const seenKeys = new Set();

    rawStrategies.forEach(s => {
      const attackChainStr = (s.attack_chain || []).join(" -> ");
      // Key based on CVE and Chain to show unique paths
      const key = `${s.cve_id}|${attackChainStr}`;

      if (!seenKeys.has(key)) {
        seenKeys.add(key);
        uniqueStrategies.push(s);
      }
    });

    const model5HTML = uniqueStrategies.length ? `
      <h3>Exploitation Strategies</h3>
      ${uniqueStrategies.map(s => {
      // Build ExploitDB Links if they exist
      let refHTML = "";
      if (s.exploit_db_reference && s.exploit_db_reference.length > 0) {
        refHTML = `<div style="margin-top:5px;"><strong>Exploit References:</strong><ul>`;
        s.exploit_db_reference.forEach(ref => {
          refHTML += `<li><a href="${ref.url}" target="_blank" style="color: #38bdf8;">${ref.id}</a> - ${ref.title}</li>`;
        });
        refHTML += `</ul></div>`;
      }

      const isVerified = s.exploit_db_reference && s.exploit_db_reference.length > 0;

      return `
        <div class="strategy-card card" style="border-left: 4px solid ${isVerified ? '#ef4444' : '#94a3b8'};">
          <h4>${s.service}</h4>
          
          <div style="display: flex; justify-content: space-between; margin-bottom: 10px;">
             <span class="badge" style="background: ${isVerified ? '#ef4444' : '#94a3b8'}; color: white;">
                ${s.evidence_status || "Unknown Status"}
             </span>
             <span><strong>CVE:</strong> ${s.cve_id} (Severity: ${s.severity})</span>
          </div>

          ${(s.attack_chain && s.attack_chain.length > 0) ? `
          <p class="card-text">
            <strong>Attack Chain:</strong><br>
            <span style="font-family: monospace; color: #ef4444; font-weight: bold;">
              ${s.attack_chain.join(" <span style='color: #64748b;'>→</span> ")}
            </span>
          </p>` : `
          <p class="card-text">
            <strong>Attack Chain:</strong> <span style="color: #94a3b8; font-style: italic;">Not Available</span>
            <br>
            <small style="color: #64748b;">(Reason: No verified public exploit exists; exploitation path cannot be determined.)</small>
          </p>
          `}
          
          <p class="card-text" style="font-style: italic; color: #94a3b8; margin-top: 10px;">
             "${s.explanation}"
          </p>

          ${refHTML}
          
          <div style="margin-top: 10px; font-size: 0.85rem; color: #64748b;">
             MITRE: ${s.mitre_technique}
          </div>
        </div>
      `;
    }).join("")}
    ` : "<p>No exploitation strategies generated (System appears secure or no known CVEs).</p>";

    /* ===============================
       FINAL RENDER
    =============================== */

    // Process Model 6 HTML into Table
    const model6Data = r.model6 || [];
    let model6HTML = "";
    if (model6Data.length) {
      model6HTML = `
        <div class="risk-table-container">
          <h3>Vulnerability Risk Assessment</h3>
          <table class="vuln-table">
            <thead>
              <tr>
                <th>CVE ID</th>
                <th>Service</th>
                <th>Port</th>
                <th>CVSS</th>
                <th>Risk Level</th>
              </tr>
            </thead>
            <tbody>
              ${model6Data.map(v => {
        const portDisplay = (v.port !== undefined && v.port !== null && v.port !== "") ? v.port : "N/A";
        const cvssDisplay = (v.cvss !== undefined && v.cvss !== null && v.cvss !== "") ? v.cvss : "N/A";
        const riskClass = (v.risk_level || "unknown").toLowerCase();

        return `
                <tr>
                  <td>${v.cve_id || "N/A"}</td>
                  <td>${v.service || "N/A"}</td>
                  <td>${portDisplay}</td>
                  <td>${cvssDisplay}</td>
                  <td>
                    <span class="risk-badge ${riskClass}">
                      ${v.risk_level || "Unknown"}
                    </span>
                  </td>
                </tr>`;
      }).join("")}
            </tbody>
          </table>
        </div>
      `;
    }

    /* ===============================
       MODEL 7 – Recommendations (Async Container)
    =============================== */
    // We render an empty container and handle fetching on button click
    const recommendationsHTML = `
      <div id="recommendations-section" class="recommendations-section" style="display: none;">
        <h3>Recommended Patches & Remediation</h3>
        <p class="card-text" style="margin-bottom: 16px;">One recommendation per vulnerability. Apply fixes in priority order.</p>
        <div id="recommendations-content">
           <p class="card-text">Loading recommendations...</p>
        </div>
      </div>
    `;

    reportContent.innerHTML = `
      <div class="summary card">
        <strong>Total Candidates:</strong> ${r.total_candidates || 0}
      </div>

      <h3>Clusters</h3>
      ${clustersHTML}

      <h3>Examples</h3>
      <ul>${examplesHTML}</ul>

      ${model2HTML}
      ${model3HTML}
      ${model4HTML}
      ${model5StatsHTML}
      ${model5HTML}
      ${model6HTML}
      ${recommendationsHTML}
    `;

    const patchBtn = document.getElementById("patch-btn");
    if (patchBtn) {
      // Logic for Model 7 async generation
      let isRecommendationsVisible = false;
      let hasGenerated = false;

      patchBtn.onclick = async () => {
        const recSection = document.getElementById("recommendations-section");
        const recContent = document.getElementById("recommendations-content");

        // Toggle hide if already generated and visible
        if (isRecommendationsVisible) {
          recSection.style.display = "none";
          patchBtn.textContent = "Show Recommendation";
          isRecommendationsVisible = false;
          return;
        }

        // Show if already generated but hidden
        if (hasGenerated) {
          recSection.style.display = "block";
          patchBtn.textContent = "Hide Recommendation";
          isRecommendationsVisible = true;
          recSection.scrollIntoView({ behavior: "smooth", block: "start" });
          return;
        }

        // --- Execute Model 7 Endpoint ---
        patchBtn.textContent = "Loading...";
        patchBtn.disabled = true;
        recSection.style.display = "block";
        recContent.innerHTML = "<p class='card-text'>Generating intelligent recommendations... please wait.</p>";
        recSection.scrollIntoView({ behavior: "smooth", block: "start" });

        try {
          const payload = {};
          if (reportId) payload.report_id = reportId;
          if (domain) payload.domain = domain;

          const recResp = await fetch("http://localhost:5000/generate_recommendations", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
          });

          if (!recResp.ok) throw new Error("Failed to generate recommendations");

          const recData = await recResp.json();
          const recArray = recData.recommendations || [];

          if (recArray.length === 0) {
            recContent.innerHTML = "<p class='card-text'>No vulnerabilities in this report; no recommendations to show.</p>";
          } else {
            recContent.innerHTML = `
              <div class="recommendation-cards">
                ${recArray.map(rec => {
              let remList = "";
              if (Array.isArray(rec.remediation)) {
                remList = "<ul>" + rec.remediation.map(step => `<li>${step}</li>`).join("") + "</ul>";
              } else {
                remList = rec.remediation || "—";
              }

              let refListHTML = "";
              if (Array.isArray(rec.references) && rec.references.length > 0) {
                refListHTML = `<div class="rec-row" style="margin-top: 10px;"><strong>References:</strong><ul style="margin: 5px 0; padding-left: 20px;">` +
                  rec.references.map(u => `<li><a href="${u}" target="_blank" rel="noopener">${u}</a></li>`).join("") +
                  `</ul></div>`;
              }

              return `
                  <div class="recommendation-card card">
                    <div class="rec-row" style="display:flex; justify-content:space-between;">
                        <span><strong>CVE:</strong> ${rec.cve_id || "N/A"}</span>
                        <span class="risk-badge ${(rec.severity || rec.risk_level || "unknown").toLowerCase()}">${rec.priority || rec.severity || "Unknown"}</span>
                    </div>
                    <div class="rec-row" style="margin-top: 5px;"><strong>Service & Port:</strong> ${rec.service || "N/A"} (Port ${rec.port !== undefined && rec.port !== null ? rec.port : "N/A"})</div>
                    <div class="rec-row" style="margin-top: 10px; font-style: italic;"><strong>Explanation:</strong> ${rec.explanation || "—"}</div>
                    <div class="rec-row" style="margin-top: 5px; font-style: italic; color: #f87171;"><strong>Attacker Perspective:</strong> ${rec.attacker_perspective || "—"}</div>
                    <div class="rec-row rec-remediation" style="margin-top: 10px; border-top: 1px solid rgba(255,255,255,0.1); padding-top: 10px;">
                        <strong>Actionable Remediation:</strong><br>${remList}
                    </div>
                    ${refListHTML}
                    <div class="rec-row" style="margin-top: 15px;">
                        <a href="/download_fix_script?cve_id=${encodeURIComponent(rec.cve_id || "N/A")}&service=${encodeURIComponent(rec.service || "")}&port=${encodeURIComponent(rec.port || "")}&host=${encodeURIComponent(rec.host || "")}" class="btn btn-sm btn-outline-info download-fix-btn">Download Fix Script</a>
                    </div>
                  </div>
                `}).join("")}
              </div>
            `;
          }

          hasGenerated = true;
          isRecommendationsVisible = true;
          patchBtn.textContent = "Hide Recommendation";
          patchBtn.disabled = false;

        } catch (error) {
          console.error(error);
          recContent.innerHTML = `<p style="color:red;">Error loading recommendations: ${error.message}</p>`;
          patchBtn.textContent = "Show Recommendation";
          patchBtn.disabled = false;
        }
      };

      const downloadBtn = document.getElementById("download-btn");
      if (downloadBtn) {
        downloadBtn.onclick = () => {
          let url = "/download_report?";
          if (reportId) url += `report_id=${encodeURIComponent(reportId)}`;
          else if (domain) url += `domain=${encodeURIComponent(domain)}`;
          window.location.href = url;
        };
      }
    }

  } catch (err) {
    console.error(err);
    reportContent.innerHTML =
      `< p style = "color:red;" > Error loading report: ${err.message}</p > `;
  }
});
