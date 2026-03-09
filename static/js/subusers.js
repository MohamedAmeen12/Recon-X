document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("subUserForm");
  if (!form) return;

  const hintEl = document.getElementById("subUserHint");

  // Optionally show allowed domains to the main user
  fetch("/user/profile")
    .then((res) => res.json())
    .then((data) => {
      const allowed = (data.allowed_domains || []).join(", ");
      if (allowed && hintEl) {
        hintEl.textContent =
          "You can assign one or more of your allowed domains (from this list): " +
          allowed +
          ". Separate multiple domains by commas or new lines.";
      }
    })
    .catch(() => {});

  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();

    const name = document.getElementById("subUserName").value.trim();
    const email = document.getElementById("subUserEmail").value.trim();
    const password = document.getElementById("subUserPassword").value;
    const domainsRaw = document.getElementById("subUserDomains").value.trim();

    if (!name || !email || !password || !domainsRaw) {
      alert("All fields are required.");
      return;
    }

    const parts = domainsRaw
      .split(/[\n,]+/)
      .map((p) => p.trim().toLowerCase())
      .filter(Boolean);
    const uniqueDomains = Array.from(new Set(parts));

    if (!uniqueDomains.length) {
      alert("Please enter at least one domain for the sub-user.");
      return;
    }

    try {
      const resp = await fetch("/subusers", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name,
          email,
          password,
          domains: uniqueDomains,
        }),
      });

      const data = await resp.json();
      if (resp.ok) {
        alert("Sub-user created successfully.");
        form.reset();
      } else {
        alert(data.message || "Failed to create sub-user.");
      }
    } catch (err) {
      console.error("Error creating sub-user:", err);
      alert("Error creating sub-user.");
    }
  });
});

