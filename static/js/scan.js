document.addEventListener("DOMContentLoaded", () => {

  const form = document.querySelector(".scan-form");
  const domainInput = document.getElementById("domain-input");
  const submitBtn = document.getElementById("scan-btn");

  // Arrays to hold scoped contexts
  let primaryDomain = "";
  let additionalDomains = [];

  const resultsContainer = document.createElement("div");
  resultsContainer.id = "scan-results";
  resultsContainer.style.margin = "20px auto";
  resultsContainer.style.maxWidth = "600px";
  resultsContainer.style.background = "rgba(0,0,0,0.4)";
  resultsContainer.style.padding = "16px";
  resultsContainer.style.borderRadius = "8px";
  resultsContainer.style.border = "1px solid rgba(255,255,255,0.1)";
  resultsContainer.style.display = "none";

  const formParent = form ? form.parentNode : document.body;
  if(formParent) formParent.appendChild(resultsContainer);

  function showMessage(msg, isError = false) {
    resultsContainer.style.display = "block";
    resultsContainer.innerHTML = `
      <p style="color:${isError ? "#ef4444" : "#10b981"}; margin:0 0 12px 0; font-weight: bold; font-family: monospace;">${msg}</p>
    `;
  }

  async function loadAllowedDomains() {
    try {
      const resp = await fetch("/user/profile");
      if (!resp.ok) throw new Error("Unable to load user profile.");
      const data = await resp.json();
      
      primaryDomain = String(data.primary_domain || "");
      additionalDomains = (data.additional_domains || []).map((d) => String(d));

      const primaryDisp = document.getElementById("primary-domain-display");
      if(primaryDisp) primaryDisp.textContent = primaryDomain || "None tied to account";
      
      const additionalList = document.getElementById("additional-domains-list");
      if (additionalList) {
          additionalList.innerHTML = additionalDomains.length > 0 
              ? additionalDomains.map(d => `<li><i class="ph-bold ph-caret-right text-emerald-500 mr-1"></i> ${d}</li>`).join("")
              : `<li class="text-[11px] text-gray-500 italic">No alternative scopes bound</li>`;
      }
    } catch (err) {
      console.error("Failed to load scoping domains:", err);
    }
  }

  // ============================
  // Additional Scopes Validation
  // ============================
  let currentAddingDomain = "";
  document.getElementById("toggleAddDomainBtn")?.addEventListener("click", () => {
      const f = document.getElementById("addDomainForm");
      f.classList.toggle("hidden");
  });
  
  document.getElementById("generateNewTokenBtn")?.addEventListener("click", async () => {
      const dIn = document.getElementById("newDomainInput").value.trim();
      if(!dIn) return alert("Enter a valid external domain.");
      try {
          const res = await fetch("/generate-token", {
              method: "POST", headers: {"Content-Type":"application/json"},
              body: JSON.stringify({domain: dIn})
          });
          const data = await res.json();
          if (res.ok) {
              currentAddingDomain = dIn;
              const clnD = currentAddingDomain.startsWith("http") ? currentAddingDomain.replace(/\/$/, "") : "https://" + currentAddingDomain;
              document.getElementById("newVerifyUrl").innerText = `${clnD}/reconx-verification.txt`;
              document.getElementById("newVerifyToken").innerText = data.token;
              
              document.getElementById("newVerificationStep").classList.remove("hidden");
          } else { alert(data.error || "Generation error."); }
      } catch (err) { alert("Network exception."); }
  });
  
  document.getElementById("verifyNewBtn")?.addEventListener("click", async () => {
      const btn = document.getElementById("verifyNewBtn");
      const orig = btn.innerHTML;
      btn.innerHTML = "Verifying Route...";
      btn.disabled = true;
      try {
          const res = await fetch("/verify-additional-domain", {
              method: "POST", headers: {"Content-Type":"application/json"},
              body: JSON.stringify({domain: currentAddingDomain})
          });
          const data = await res.json();
          if (res.ok) {
              alert("Alternative Scope Bound Successfully!");
              loadAllowedDomains(); // Refresh array locally
              document.getElementById("addDomainForm").classList.add("hidden");
              document.getElementById("newDomainInput").value = "";
              document.getElementById("newVerificationStep").classList.add("hidden");
          } else { alert(data.error || "Validation sequence rejected."); }
      } catch (err) { alert("Network exception."); }
      btn.innerHTML = orig; btn.disabled = false;
  });

  async function postJSON(url, body) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 600000); // 10m
    try {
      const resp = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      return resp;
    } catch (error) {
      clearTimeout(timeoutId);
      if (error.name === 'AbortError') throw new Error('Request timeout limit hit.');
      throw error;
    }
  }

  // ============================
  // SCAN BURST QUEUEING MODULE
  // ============================
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    resultsContainer.style.display = "none";

    const inputData = domainInput.value.trim();
    if (!inputData) {
      showMessage("Please insert targets into the text area.", true);
      return;
    }

    const targets = inputData.split(/[\n,]+/).map(t => t.trim().toLowerCase()).filter(Boolean);
    const uniqueTargets = Array.from(new Set(targets));

    if (!uniqueTargets.length) return;

    submitBtn.disabled = true;
    domainInput.disabled = true;
    
    showMessage(`Starting burst scan for ${uniqueTargets.length} discovered target(s)...`);

    for (let i = 0; i < uniqueTargets.length; i++) {
        const target = uniqueTargets[i];
        try {
            resultsContainer.innerHTML = `<p style="color:#10b981; margin:0; font-family:monospace; font-weight:bold;">[${i+1}/${uniqueTargets.length}] Interrogating ${target}...</p>`;
            
            const resp = await postJSON("/scan_domain", {
              domain: target,
              include_tech_scan: true
            });

            if (!resp.ok) {
              const errData = await resp.json().catch(() => ({}));
              alert(`Scan halted on ${target} due to API Rejection: ${errData.error || errData.message}`);
              break; // Abort sequential queue on hard blocks (e.g. 403 Forbidden rules)
            }
        } catch (err) {
            let errorMsg = err.message;
            if (err.message.includes('Failed to fetch') || err.message.includes('NetworkError')) {
              errorMsg = 'Server unreachable drop detected.';
            }
            alert(`Scan halted critically on ${target}: ${errorMsg}`);
            break;
        }
    }
    
    showMessage("✅ Execution Pipeline Completed. Redirecting to consolidated reports...", false);
    setTimeout(() => {
        window.location.href = `/reports`; // Just drop them to their central dashboard history
    }, 2000);

    submitBtn.disabled = false;
    domainInput.disabled = false;
  });

  // Load the scoped domains for the logged-in user
  loadAllowedDomains();


});

