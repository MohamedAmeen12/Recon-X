document.getElementById("signupForm").addEventListener("submit", async function (e) {
  e.preventDefault();

  const name = document.getElementById("name").value.trim();
  const email = document.getElementById("email").value.trim();
  const domainsRaw = document.getElementById("domains").value.trim();
  const password = document.getElementById("password").value;
  const confirmPassword = document.getElementById("confirmPassword").value;

  // Basic client-side domain parsing and validation
  const parts = domainsRaw.split(/[\n,]+/).map((p) => p.trim().toLowerCase()).filter(Boolean);
  const uniqueDomains = Array.from(new Set(parts));

  if (!uniqueDomains.length) {
    alert("Please enter at least one domain to scan.");
    return;
  }

  if (password !== confirmPassword) {
    alert("Passwords do not match!");
    return;
  }

  try {
    const response = await fetch("/signup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: name,
        email: email,
        password: password,
        domains: uniqueDomains,
      })
    });

    const data = await response.json();

    if (response.ok) {
      // ✅ Show backend trust status to the user
      alert(`Signup successful! Your account status is: ${data.status.toUpperCase()}`);
      
      // Redirect if verified, otherwise keep them on signup for review
      if (data.status === "verified") {
        window.location.href = "login.html";
      } 
    } else {
      alert(data.message || "Signup failed. Please try again.");
      console.error("Signup failed:", data);
    }
  } catch (err) {
    console.error("Error connecting to server:", err);
    alert("Could not connect to the server. Please try again later.");
  }
});
