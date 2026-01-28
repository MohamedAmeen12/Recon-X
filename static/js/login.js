document.getElementById("loginForm").addEventListener("submit", async (event) => {
  event.preventDefault();

  const email = document.getElementById("email").value.trim();
  const password = document.getElementById("password").value.trim();

  if (!email || !password) {
    return;
  }

  try {
    const response = await fetch("http://localhost:5000/login", {
      method: "POST",
      credentials: "include", 
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password })
    });

    const data = await response.json();

    if (response.ok) {
      // ✅ Check if account is pending
      if (data.status && data.status === "pending") {
        alert("Your account is waiting for admin verification.");
        return;
      }

      console.log("User logged in:", data);
      localStorage.setItem("userEmail", data.email);
      localStorage.setItem("role", data.role);

      if (data.role === "admin") {
        window.location.href = "/admin";
      } else {
        window.location.href = "home.html";
      }
    } else {
      console.error("Login failed:", data.message);
      alert(data.message); // optional
    }
  } catch (error) {
    console.error("Error connecting to server:", error);
  }
});

