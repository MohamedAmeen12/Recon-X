document.addEventListener("DOMContentLoaded", () => {

  const form = document.querySelector(".scan-form");
  const domainInput = document.getElementById("domain-input");
  const submitBtn = document.getElementById("scan-btn");

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

    const domain = domainInput.value.trim();
    if (!domain) {
      showMessage("Please enter a domain (e.g., example.com).", true);
      return;
    }

    submitBtn.disabled = true;
    const origText = submitBtn.textContent;
    submitBtn.textContent = "Scanning...";

    try {
      const resp = await postJSON("http://localhost:5000/scan_domain", { 
        domain: domain,
        include_tech_scan: true 
      });

      if (resp.ok) {
        showMessage("✅ Scan completed! Redirecting to report...");

        setTimeout(() => {
          window.location.href = `/report?domain=${encodeURIComponent(domain)}`;
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

});

