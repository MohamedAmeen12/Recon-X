document.getElementById("signupForm").addEventListener("submit", async function (e) {
  e.preventDefault();

  const name = document.getElementById("name").value.trim();
  const email = document.getElementById("email").value.trim();
  const domainsRaw = document.getElementById("domains").value.trim();
  const password = document.getElementById("password").value;
  const confirmPassword = document.getElementById("confirmPassword").value;

  if (password.length < 8 || !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    alert("Please ensure your password meets all requirements.");
    return;
  }

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

// Password Requirements Logic
const passwordInput = document.getElementById("password");
const reqLength = document.getElementById("req-length");
const reqSpecial = document.getElementById("req-special");

if (passwordInput && reqLength && reqSpecial) {
  passwordInput.addEventListener("input", function () {
    const val = passwordInput.value;

    // Check length
    if (val.length >= 8) {
      reqLength.classList.remove("invalid");
      reqLength.classList.add("valid");
      reqLength.innerHTML = "✅ 8 characters or more";
    } else {
      reqLength.classList.remove("valid");
      reqLength.classList.add("invalid");
      reqLength.innerHTML = "❌ 8 characters or more";
    }

    // Check special character
    const specialCharRegex = /[!@#$%^&*(),.?":{}|<>]/;
    if (specialCharRegex.test(val)) {
      reqSpecial.classList.remove("invalid");
      reqSpecial.classList.add("valid");
      reqSpecial.innerHTML = "✅ At least one special character";
    } else {
      reqSpecial.classList.remove("valid");
      reqSpecial.classList.add("invalid");
      reqSpecial.innerHTML = "❌ At least one special character";
    }
  });
}
