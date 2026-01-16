 const toggleBtn = document.getElementById("darkModeToggle");

    // Load saved theme
    if (localStorage.getItem("theme") === "dark") {
        document.body.classList.add("dark-mode");
        toggleBtn.textContent = "☀️";
    }

    toggleBtn.addEventListener("click", () => {
        document.body.classList.toggle("dark-mode");

        if (document.body.classList.contains("dark-mode")) {
            localStorage.setItem("theme", "dark");
            toggleBtn.textContent = "☀️";
        } else {
            localStorage.setItem("theme", "light");
            toggleBtn.textContent = "🌙";
        }
    });