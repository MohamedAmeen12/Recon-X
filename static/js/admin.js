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
        <td>${u.company || "—"}</td>
        <td>${u.created_at ? new Date(u.created_at).toLocaleString() : "—"}</td>
        <td>
          <button class="delete-btn" onclick="deleteUser('${u._id}')">Delete</button>
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
  const company = document.getElementById("company").value.trim();
  const password = document.getElementById("password").value.trim();

  if (!username || !email || !password) {
    alert("All fields except company are required!");
    return;
  }

  const res = await fetch(`${BASE_URL}/admin/add_user`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, email, company, password }),
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

// Auto-load users
window.addEventListener("DOMContentLoaded", fetchUsers);
