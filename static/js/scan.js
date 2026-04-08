document.addEventListener("DOMContentLoaded", () => {

  const form         = document.querySelector(".scan-form");
  const domainSelect = document.getElementById("domain-select");
  const submitBtn    = document.getElementById("scan-btn");
  const btnIcon      = document.getElementById("scan-btn-icon");
  const btnLabel     = document.getElementById("scan-btn-label");

  // Progress bar elements
  const progressWrapper = document.getElementById("scan-progress-wrapper");
  const progressBar     = document.getElementById("scan-progress-bar");
  const progressPct     = document.getElementById("scan-progress-pct");
  const progressStage   = document.getElementById("scan-progress-stage");

  let allowedDomains  = [];
  let progressTimer   = null;   // rAF / interval handle
  let currentProgress = 0;      // 0–100

  // ─── Stage definitions (label + target % ceiling) ────────────────────────
  const STAGES = [
    { pct: 8,  label: "Initializing reconnaissance engine…"        },
    { pct: 18, label: "Resolving DNS records & subdomains…"         },
    { pct: 30, label: "Enumerating open ports & services…"          },
    { pct: 44, label: "Fingerprinting web technologies…"            },
    { pct: 57, label: "Running vulnerability pattern analysis…"     },
    { pct: 68, label: "Crawling exposed endpoints…"                 },
    { pct: 78, label: "Analysing SSL/TLS configuration…"            },
    { pct: 86, label: "Correlating threat intelligence feeds…"      },
    { pct: 93, label: "Running AI-powered risk scoring…"            },
    { pct: 97, label: "Compiling final reconnaissance report…"      },
  ];

  // ─── Helpers ──────────────────────────────────────────────────────────────
  function setProgress(pct) {
    currentProgress = Math.min(Math.max(pct, 0), 100);
    const rounded   = Math.round(currentProgress);
    progressBar.style.width = rounded + "%";
    progressPct.textContent = rounded + "%";

    // Determine current stage label
    for (let i = STAGES.length - 1; i >= 0; i--) {
      if (currentProgress >= STAGES[i].pct) {
        progressStage.textContent = STAGES[i].label;
        break;
      }
    }
    if (currentProgress < STAGES[0].pct) {
      progressStage.textContent = "Initializing reconnaissance engine…";
    }
    if (currentProgress >= 100) {
      progressStage.textContent = "✅ Scan complete — building report…";
    }
  }

  function startProgressSimulation() {
    currentProgress = 0;
    setProgress(0);
    progressWrapper.style.display = "block";

    // Animate: crawl slowly toward 97%, never reaching 100 until server responds
    let lastTime = null;
    // Speed: starts fast then exponentially slows (simulates unknown remaining work)
    function tick(timestamp) {
      if (!lastTime) lastTime = timestamp;
      const elapsed = (timestamp - lastTime) / 1000; // seconds
      lastTime = timestamp;

      // Rate: starts at ~12%/s, decays as we approach 97
      const remaining = 97 - currentProgress;
      if (remaining > 0) {
        const rate = Math.max(0.06, remaining * 0.05); // slows as it fills
        setProgress(currentProgress + rate * elapsed * 10);
      }

      if (currentProgress < 97) {
        progressTimer = requestAnimationFrame(tick);
      }
    }
    progressTimer = requestAnimationFrame(tick);
  }

  function stopProgressSimulation(success) {
    if (progressTimer) {
      cancelAnimationFrame(progressTimer);
      progressTimer = null;
    }

    if (success) {
      // Snap smoothly to 100%
      animateTo100();
    } else {
      // Reset with a short delay so user sees the position before hide
      setTimeout(resetProgress, 800);
    }
  }

  function animateTo100() {
    const start    = currentProgress;
    const duration = 600; // ms
    const startTs  = performance.now();

    function finish(ts) {
      const t   = Math.min((ts - startTs) / duration, 1);
      const eased = 1 - Math.pow(1 - t, 3); // ease-out cubic
      setProgress(start + (100 - start) * eased);
      if (t < 1) {
        requestAnimationFrame(finish);
      }
    }
    requestAnimationFrame(finish);
  }

  function resetProgress() {
    progressWrapper.style.display = "none";
    currentProgress = 0;
    setProgress(0);
    showForm(); // reveal form again on error
  }

  function setBtnScanning(scanning) {
    if (scanning) {
      hideForm();
    } else {
      // Only restore button state; form visibility is managed by hideForm/showForm
      submitBtn.disabled = false;
      btnIcon.className  = "ph-bold ph-rocket-launch text-lg";
      btnLabel.textContent = "Execute Scan";
    }
  }

  // ─── Form visibility helpers ──────────────────────────────────────────────
  function hideForm() {
    form.style.transition = "opacity 0.35s ease, transform 0.35s ease";
    form.style.opacity    = "0";
    form.style.transform  = "translateY(-8px)";
    form.style.pointerEvents = "none";
    // After fade-out finishes, collapse the space so only the bar shows
    setTimeout(() => {
      form.style.display = "none";
    }, 360);
  }

  function showForm() {
    form.style.display   = "";
    // Force reflow before adding the classes back
    void form.offsetHeight;
    form.style.transition = "opacity 0.4s ease, transform 0.4s ease";
    form.style.opacity    = "1";
    form.style.transform  = "translateY(0)";
    form.style.pointerEvents = "";
  }

  // ─── Results message container (inline, below progress) ──────────────────
  const resultsContainer = document.createElement("div");
  resultsContainer.id = "scan-results";
  resultsContainer.style.display = "none";
  resultsContainer.style.marginTop = "12px";

  // Insert after progress wrapper
  progressWrapper.insertAdjacentElement("afterend", resultsContainer);

  function showMessage(msg, isError = false) {
    resultsContainer.style.display = "block";
    resultsContainer.className = isError ? "scan-msg scan-msg--error" : "scan-msg scan-msg--success";
    resultsContainer.innerHTML = `<i class="ph-bold ${isError ? 'ph-warning' : 'ph-check-circle'}"></i> ${msg}`;
  }

  function hideMessage() {
    resultsContainer.style.display = "none";
    resultsContainer.textContent = "";
  }

  // ─── Load user domains ────────────────────────────────────────────────────
  async function loadAllowedDomains() {
    try {
      const resp = await fetch("/user/profile");
      if (!resp.ok) throw new Error("Unable to load user profile.");
      const data = await resp.json();
      allowedDomains = (data.allowed_domains || []).map((d) => String(d).toLowerCase());

      if (!allowedDomains.length) {
        domainSelect.innerHTML = '<option value="">No registered domains available</option>';
        domainSelect.disabled  = true;
        submitBtn.disabled     = true;
        showMessage("You do not have any registered domains. Please contact an administrator.", true);
        return;
      }

      domainSelect.innerHTML =
        '<option value="">Select a domain to scan</option>' +
        allowedDomains.map((d) => `<option value="${d}">${d}</option>`).join("");
      domainSelect.disabled = false;
      submitBtn.disabled    = false;
    } catch (err) {
      console.error("Failed to load allowed domains:", err);
      domainSelect.innerHTML = '<option value="">Error loading domains</option>';
      domainSelect.disabled  = true;
      submitBtn.disabled     = true;
      showMessage("Could not load your registered domains. Please refresh the page.", true);
    }
  }

  // ─── POST helper with timeout ─────────────────────────────────────────────
  async function postJSON(url, body) {
    const controller = new AbortController();
    const timeoutId  = setTimeout(() => controller.abort(), 600000); // 10 min
    try {
      const resp = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      clearTimeout(timeoutId);
      return resp;
    } catch (error) {
      clearTimeout(timeoutId);
      if (error.name === "AbortError") {
        throw new Error("Request timeout — scan is taking too long. Please try again.");
      }
      throw error;
    }
  }

  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    hideMessage();

    const domain = domainSelect.value.trim().toLowerCase();
    if (!domain) { showMessage("Please select a domain to scan.", true); return; }

    if (!allowedDomains.includes(domain)) {
      showMessage("You are only allowed to scan domains registered to your account.", true);
      return;
    }

    setBtnScanning(true);   // hides form, fades out
    startProgressSimulation();

    try {
      const resp = await postJSON("/scan_domain", { domain, include_tech_scan: true });

      if (resp.ok) {
        const data = await resp.json();
        stopProgressSimulation(true);
        showMessage("Scan complete! Redirecting to your report…");

        setTimeout(() => {
          window.location.href = data.report_id
            ? `/report?report_id=${data.report_id}`
            : `/report?domain=${encodeURIComponent(domain)}`;
        }, 1800);
      } else {
        const errData = await resp.json().catch(() => ({}));
        stopProgressSimulation(false);   // triggers resetProgress → showForm
        showMessage(`Server error ${resp.status}: ${errData.message || "Unknown error"}`, true);
      }
    } catch (err) {
      stopProgressSimulation(false);     // triggers resetProgress → showForm
      let errorMsg = err.message;
      if (err.message.includes("Failed to fetch") || err.message.includes("NetworkError")) {
        errorMsg = "Cannot connect to the server. Make sure the Flask server is running.";
      }
      showMessage(`Error: ${errorMsg}`, true);
      console.error("Scan error:", err);
    }
    // NOTE: no finally setBtnScanning(false) — form is restored by showForm() on error
  });

  loadAllowedDomains();
});
