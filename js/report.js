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
    // Build quick lookup table: { "subdomain": [ports] }
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

    // Model 3: Technology Fingerprints & Vulnerabilities
    let technologiesHTML = "";
    let vulnerabilitiesHTML = "";
    
    if (r.technology_fingerprints && r.technology_fingerprints.length > 0) {
      // Display technologies
      technologiesHTML = r.technology_fingerprints.map(techResult => {
        const url = techResult.url || "N/A";
        const techs = techResult.technologies || [];
        
        if (techs.length === 0) return "";
        
        const techList = techs.map(tech => {
          const statusColor = tech.vulnerability_status === "vulnerable" ? "red" : 
                             tech.vulnerability_status === "safe" ? "green" : "orange";
          return `
            <div style="margin: 10px 0; padding: 10px; border-left: 3px solid ${statusColor}; background: #f5f5f5;">
              <strong>${tech.technology}</strong> ${tech.version ? `v${tech.version}` : ""}
              <br><small>Category: ${tech.category} | Source: ${tech.source}</small>
              <br><small>Status: <span style="color: ${statusColor}; font-weight: bold;">${tech.vulnerability_status.toUpperCase()}</span> 
              (Confidence: ${(tech.confidence * 100).toFixed(1)}%)</small>
            </div>
          `;
        }).join("");
        
        return `
          <div style="margin: 15px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px;">
            <h4 style="margin-top: 0;">${url}</h4>
            ${techList}
          </div>
        `;
      }).join("");
      
      // Display vulnerabilities (CVEs)
      const allVulns = [];
      r.technology_fingerprints.forEach(techResult => {
        (techResult.technologies || []).forEach(tech => {
          (tech.cves || []).forEach(cve => {
            allVulns.push({
              ...cve,
              technology: tech.technology,
              version: tech.version,
              url: techResult.url
            });
          });
        });
      });
      
      if (allVulns.length > 0) {
        // Sort by CVSS score (highest first)
        allVulns.sort((a, b) => (b.cvss || 0) - (a.cvss || 0));
        
        vulnerabilitiesHTML = `
          <h3>Vulnerabilities (CVEs)</h3>
          <div style="max-height: 500px; overflow-y: auto;">
            ${allVulns.map(vuln => {
              const severityColor = vuln.cvss >= 9.0 ? "darkred" : 
                                   vuln.cvss >= 7.0 ? "red" : 
                                   vuln.cvss >= 4.0 ? "orange" : "yellow";
              return `
                <div style="margin: 10px 0; padding: 12px; border-left: 4px solid ${severityColor}; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                  <div style="display: flex; justify-content: space-between; align-items: start;">
                    <div style="flex: 1;">
                      <strong style="color: ${severityColor}; font-size: 1.1em;">${vuln.cve || "UNKNOWN"}</strong>
                      <br><span style="color: #666;">${vuln.technology} ${vuln.version ? `v${vuln.version}` : ""}</span>
                      <br><span style="color: #666;">${vuln.url || ""}</span>
                    </div>
                    <div style="text-align: right;">
                      <span style="background: ${severityColor}; color: white; padding: 4px 8px; border-radius: 3px; font-weight: bold;">
                        CVSS: ${vuln.cvss || "N/A"}
                      </span>
                    </div>
                  </div>
                  <p style="margin: 8px 0 0 0; color: #333;">${vuln.description || "No description available"}</p>
                  ${vuln.severity ? `<small style="color: #666;">Severity: ${vuln.severity}</small>` : ""}
                </div>
              `;
            }).join("")}
          </div>
        `;
      }
    } else {
      technologiesHTML = "<p style='color: #666;'>No technology fingerprints available. Enable Model 3 by setting include_tech_scan=true in scan request.</p>";
    }

    reportContent.innerHTML = `
      <div class="summary">
        <p><strong>Total Candidates:</strong> ${r.total_candidates || 0}</p>
        <p><strong>Resolved:</strong> ${r.resolved || 0}</p>
        <p><strong>Live HTTP:</strong> ${r.live_http || 0}</p>
        <p><strong>Elapsed:</strong> ${r.elapsed_seconds?.toFixed(1)}s</p>
      </div>
      <h3>Clusters</h3>
      ${clustersHTML || "<p>No clusters found.</p>"}
      <h3>Examples</h3>
      <ul>${examplesHTML}</ul>
      ${technologiesHTML ? `<h3>Detected Technologies (Model 3)</h3>${technologiesHTML}` : ""}
      ${vulnerabilitiesHTML || ""}
    `;
  } catch (err) {
    console.error(err);
    reportContent.innerHTML = `<p style='color:red;'>Error loading report: ${err.message}</p>`;
  }
});
