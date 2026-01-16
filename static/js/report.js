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

  try {
    const resp = await fetch(`http://localhost:5000/get_report?domain=${encodeURIComponent(domain)}`);
    if (!resp.ok) {
      throw new Error("Failed to load report");
    }
    const data = await resp.json();

    if (!data.result) {
      reportContent.innerHTML = "<p>No report data found for this domain.</p>";
      return;
    }

    const r = data.result;

    // ====================================================
    // MODEL 1 DATA (EXISTING – UNCHANGED)
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

        return `
          <li>
            <strong>${sub}</strong>
            <span style="color:#3b82f6; margin-left:8px;">(${portsText})</span>
          </li>
        `;
      }).join("");

      return `
        <div class="cluster-block">
          <h4>Cluster ${c.cluster_id} (${c.size} items)</h4>
          <ul>${ex}</ul>
        </div>
      `;
    }).join("");

    const examplesHTML = (r.examples || []).map(e => `<li>${e}</li>`).join("");

    // ====================================================
    // MODEL 2: PORT SCANNING (ADDED – FIX)
    // ====================================================
    let model2HTML = "";

    if (portMap && Object.keys(portMap).length > 0) {
      model2HTML = `
        <h3>Open Ports & Services (Model 2)</h3>
        ${Object.entries(portMap).map(([sub, ports]) => {
          if (!ports || ports.length === 0) {
            return `
              <div class="port-block">
                <strong>${sub}</strong>
                <p>No open ports detected</p>
              </div>
            `;
          }

          return `
            <div class="port-block">
              <strong>${sub}</strong>
              <ul>
                ${ports.map(p => `<li>${p.port}/${p.service}</li>`).join("")}
              </ul>
            </div>
          `;
        }).join("")}
      `;
    }

    // ====================================================
    // MODEL 3: TECHNOLOGY FINGERPRINTING (EXISTING)
    // ====================================================
    let technologiesHTML = "";

    if (r.technology_fingerprints && r.technology_fingerprints.length > 0) {
      technologiesHTML = r.technology_fingerprints.map(techResult => {
        const url = techResult.url || "N/A";
        const techs = techResult.technologies || [];

        if (techs.length === 0) return "";

        const techList = techs.map(tech => {
          const statusColor =
            tech.vulnerability_status === "vulnerable" ? "red" :
            tech.vulnerability_status === "safe" ? "green" : "orange";

          return `
            <div class="tech-item">
              <strong>${tech.technology}</strong> ${tech.version ? `v${tech.version}` : ""}
              <br><small>Category: ${tech.category} | Source: ${tech.source}</small>
              <br><small>Status:
                <span style="color:${statusColor}; font-weight:bold;">
                  ${tech.vulnerability_status.toUpperCase()}
                </span>
              </small>
            </div>
          `;
        }).join("");

        return `
          <div class="tech-box">
            <h4>${url}</h4>
            ${techList}
          </div>
        `;
      }).join("");
    }

    // ====================================================
    // MODEL 4: HTTP ANOMALY DETECTION (ADDED)
    // ====================================================
    let model4HTML = "";

    if (r.http_anomalies && r.http_anomalies.length > 0) {
      model4HTML = `
        <h3>HTTP Anomaly Detection (Model 4)</h3>
        <div class="anomalies-table">
          ${r.http_anomalies.map(item => {
            const res = item.model4_result || {};
            return `
              <div class="anomaly-row">
                <strong>${item.subdomain}</strong><br>
                Status: <b>${res.status ? res.status.toUpperCase() : "UNKNOWN"}</b><br>
                Anomaly Score: ${res.anomaly_score ?? "N/A"}
                ${
                  res.signals && res.signals.length > 0
                    ? `<ul>${res.signals.map(s => `<li>${s}</li>`).join("")}</ul>`
                    : "<small>No anomaly signals detected</small>"
                }
              </div>
            `;
          }).join("")}
        </div>
      `;
    }

  
      // ====================================================
      // MODEL 5: EXPLOITATION STRATEGIES (NEW)
      // ====================================================
      let model5HTML = "";

      if (r.model5 && r.model5.strategies) {
        if (r.model5.strategies.length > 0) {
          model5HTML = `
            <h3>Exploitation Strategies (Model 5)</h3>
            <div class="model5-container">
              ${r.model5.strategies.map(s => `
                <div class="strategy-card">
                  <h4>${s.technology} ${s.version ? `v${s.version}` : ""}</h4>

                  <p><strong>Exploit Source:</strong> ${s.exploit_source}</p>
                  <p><strong>MITRE Technique:</strong> ${s.mitre_technique}</p>

                  <p><strong>Attack Chain:</strong><br>
                    ${s.attack_chain.join(" → ")}
                  </p>

                  <p>
                    <span class="badge">Ports: ${s.related_ports.join(", ")}</span>
                    <span class="badge">HTTP: ${s.http_signal}</span>
                    <span class="badge confidence ${s.confidence}">
                      Confidence: ${s.confidence.toUpperCase()}
                    </span>
                  </p>
                </div>
              `).join("")}
            </div>
          `;
        } else {
          // Show this if strategies array is empty
          model5HTML = `
            <h3>Exploitation Strategies (Model 5)</h3>
            <p><em>No exploitation strategies found for this domain.</em></p>
          `;
        }
      }






    // ====================================================
    // FINAL RENDER (ALL MODELS INCLUDED)
    // ====================================================
    reportContent.innerHTML = `
      <div class="summary">
        <p><strong>Total Candidates:</strong> ${r.total_candidates || 0}</p>
        <p><strong>Resolved:</strong> ${r.resolved || 0}</p>
        <p><strong>Live HTTP:</strong> ${r.live_http || 0}</p>
        <p><strong>Elapsed:</strong> ${r.elapsed_seconds?.toFixed(1)}s</p>
      </div>

      <h3>Clusters (Model 1)</h3>
      ${clustersHTML || "<p>No clusters found.</p>"}

      <h3>Examples (Model 1)</h3>
      <ul>${examplesHTML}</ul>

      ${model2HTML}

      ${technologiesHTML ? `<h3>Detected Technologies (Model 3)</h3>${technologiesHTML}` : ""}

      ${model4HTML}

      ${model5HTML}

    `;

  } catch (err) {
    console.error(err);
    reportContent.innerHTML = `<p style='color:red;'>Error loading report: ${err.message}</p>`;
  }
});
