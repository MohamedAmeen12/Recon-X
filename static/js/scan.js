document.addEventListener("DOMContentLoaded", () => {

  const form = document.querySelector(".scan-form");
  const domainSelect = document.getElementById("domain-select");
  const submitBtn = document.getElementById("scan-btn");
  let allowedDomains = [];

  // Message container
  const resultsContainer = document.createElement("div");
  resultsContainer.id = "scan-results";
  resultsContainer.style.margin = "20px auto";
  resultsContainer.style.maxWidth = "600px";
  resultsContainer.style.background = "white";
  resultsContainer.style.padding = "16px";
  resultsContainer.style.borderRadius = "8px";
  resultsContainer.style.boxShadow = "0 3px 10px rgba(0,0,0,0.1)";
  resultsContainer.style.display = "none";

  document.querySelector(".scan-container").appendChild(resultsContainer);

  function showMessage(msg, isError = false) {
    resultsContainer.style.display = "block";
    resultsContainer.innerHTML = `
      <p style="color:${isError ? "darkred" : "black"}; margin:0 0 12px 0;">${msg}</p>
    `;
  }

  async function loadAllowedDomains() {
    try {
      const resp = await fetch("/user/profile");
      if (!resp.ok) {
        throw new Error("Unable to load user profile.");
      }
      const data = await resp.json();
      allowedDomains = (data.allowed_domains || []).map((d) => String(d).toLowerCase());

      if (!allowedDomains.length) {
        domainSelect.innerHTML = '<option value="">No registered domains available</option>';
        domainSelect.disabled = true;
        submitBtn.disabled = true;
        showMessage(
          "You do not have any registered domains. Please contact an administrator to update your account.",
          true
        );
        return;
      }

      const optionsHtml =
        '<option value="">Select a domain to scan</option>' +
        allowedDomains.map((d) => `<option value="${d}">${d}</option>`).join("");
      domainSelect.innerHTML = optionsHtml;
      domainSelect.disabled = false;
      submitBtn.disabled = false;
    } catch (err) {
      console.error("Failed to load allowed domains:", err);
      domainSelect.innerHTML = '<option value="">Error loading domains</option>';
      domainSelect.disabled = true;
      submitBtn.disabled = true;
      showMessage(
        "Could not load your registered domains. Please refresh the page or try again later.",
        true
      );
    }
  }

  async function postJSON(url, body) {
    // Create AbortController for timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 600000); // 10 minutes timeout

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
      if (error.name === 'AbortError') {
        throw new Error('Request timeout - scan is taking too long. Please try again.');
      }
      throw error;
    }
  }

  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    resultsContainer.style.display = "none";

    const domain = domainSelect.value.trim().toLowerCase();
    if (!domain) {
      showMessage("Please select a domain to scan.", true);
      return;
    }

    // Client-side enforcement: only allow registered domains
    if (!allowedDomains.includes(domain)) {
      showMessage(
        "You are only allowed to scan the domains registered in your account.",
        true
      );
      return;
    }

    submitBtn.disabled = true;
    const origText = submitBtn.textContent;
    submitBtn.textContent = "Scanning...";

    try {

      const resp = await postJSON("/scan_domain", {
        domain: domain,
        include_tech_scan: true
      });

      if (resp.ok) {
        const data = await resp.json();
        showMessage("✅ Scan completed! Redirecting to report...");

        setTimeout(() => {
          if (data.report_id) {
            window.location.href = `/report?report_id=${data.report_id}`;
          } else {
            // Fallback for some reason
            window.location.href = `/report?domain=${encodeURIComponent(domain)}`;
          }
        }, 1500);
      } else {
        const errData = await resp.json().catch(() => ({}));
        showMessage(`Server error: ${resp.status} ${errData.message || ""}`, true);
      }
    } catch (err) {
      let errorMsg = err.message;
      if (err.message.includes('Failed to fetch') || err.message.includes('NetworkError')) {
        errorMsg = 'Cannot connect to server. Make sure Flask server is running on http://localhost:5000';
      }
      showMessage(`Error: ${errorMsg}`, true);
      console.error('Scan error:', err);
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = origText;
    }
  });

  // Load the allowed domains for the logged-in user
  loadAllowedDomains();

});

