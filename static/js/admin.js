const BASE_URL = "http://localhost:5000";

// Fetch users and display in table
async function fetchUsers() {
  try {
    const response = await fetch(`${BASE_URL}/admin/get_users`);
    if (!response.ok) throw new Error("Failed to fetch users");
    const users = await response.json();

    const tableBody = document.getElementById("userTableBody");
    tableBody.innerHTML = "";

    users.forEach((u, index) => {
      const row = document.createElement("tr");
      row.innerHTML = `
        <td>${index + 1}</td>
        <td>${u.username}</td>
        <td>${u.email}</td>
        <td>${u.role || "user"}</td>
        <td>${u.created_at ? new Date(u.created_at).toLocaleString() : "—"}</td>
        <td>
          <button class="action-btn" onclick="viewUserDomains('${u._id}')">View Domains</button>
          <button class="action-btn delete-btn" onclick="deleteUser('${u._id}')">Delete</button>
        </td>
      `;
      tableBody.appendChild(row);
    });

  } catch (err) {
    console.error("Fetch error:", err);
    alert("Failed to load users.");
  }
}

// Add a new user
async function addUser(event) {
  event.preventDefault();
  const username = document.getElementById("username").value.trim();
  const email = document.getElementById("email").value.trim();
  const password = document.getElementById("password").value.trim();

  if (!username || !email || !password) {
    alert("Username, email, and password are required!");
    return;
  }

  const res = await fetch(`${BASE_URL}/admin/add_user`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, email, password }),
  });

  const data = await res.json();
  alert(data.message);
  fetchUsers();
  document.getElementById("addUserForm").reset();
}

// Delete user
async function deleteUser(userId) {
  if (!confirm("Are you sure you want to delete this user?")) return;

  const res = await fetch(`${BASE_URL}/admin/delete_user/${userId}`, {
    method: "DELETE",
  });

  const data = await res.json();
  alert(data.message);
  fetchUsers();
}

// View domains for a specific user
async function viewUserDomains(userId) {
  try {
    const res = await fetch(`${BASE_URL}/admin/get_user_domains/${userId}`);
    const data = await res.json();

    if (!res.ok) {
      alert(data.message || "Failed to load user domains.");
      return;
    }

    const headerEl = document.getElementById("userDomainsHeader");
    const contentEl = document.getElementById("userDomainsContent");

    headerEl.textContent = `${data.username} (${data.email})`;

    const allowedArr = data.allowed_domains || [];
    const scannedArr = data.scanned_domains || [];

    const allowedHtml = allowedArr.length
      ? `<div class="domain-chip-row">${allowedArr
          .map((d) => `<span class="domain-chip">${d}</span>`)
          .join("")}</div>`
      : `<span class="domain-chip badge-empty">No allowed domains configured</span>`;

    const scannedHtml = scannedArr.length
      ? `<div class="domain-chip-row">${scannedArr
          .map((d) => `<span class="domain-chip">${d}</span>`)
          .join("")}</div>`
      : `<span class="domain-chip badge-empty">No scans have been run yet</span>`;

    contentEl.innerHTML = `
      <div class="domain-section">
        <div class="domain-section-title">Allowed domains</div>
        ${allowedHtml}
      </div>
      <div class="domain-section">
        <div class="domain-section-title">Domains scanned by this user</div>
        ${scannedHtml}
      </div>
    `;
  } catch (err) {
    console.error("Failed to load user domains:", err);
    alert("Failed to load user domains.");
  }
}

// Auto-load users
window.addEventListener("DOMContentLoaded", fetchUsers);
