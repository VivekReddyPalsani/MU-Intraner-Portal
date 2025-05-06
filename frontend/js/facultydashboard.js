
  const token = localStorage.getItem("token");
  const user = JSON.parse(localStorage.getItem("user"));

  if (!token || !user) {
    alert("Please login first!");
    window.location.href = "signin.html";
  } else {
    // Prevent students from accessing this page
    if (user.role !== "faculty") {
      alert("Unauthorized: Redirecting to student dashboard.");
      window.location.href = "index.html";
    }

    // Update UI
    document.querySelectorAll(".username-placeholder").forEach(el => {
      el.textContent = user.name;
    });

    document.querySelectorAll(".userrole-placeholder").forEach(el => {
      el.textContent = user.role.charAt(0).toUpperCase() + user.role.slice(1);
    });
  }

  function logout() {
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    window.location.href = "signin.html";
  }
  document.addEventListener("DOMContentLoaded", () => {
    loadFacultySchedule();
  });
  
  async function loadFacultySchedule() {
    const token = localStorage.getItem("token");
    const tbody = document.getElementById("faculty-schedule");
    if (!tbody) return;

    try {
      const res = await fetch("https://mu-intraner-portal.onrender.com/api/faculty/schedule/today", {
        headers: {
          Authorization: "Bearer " + token
        }
      });
  
      const data = await res.json();
      console.log("✅ Fetched from API:", data);
      tbody.innerHTML = "";
  
      if (!Array.isArray(data) || data.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="text-center text-muted">No classes scheduled today.</td></tr>`;
        return;
      }
  
      data.forEach(entry => {
        const row = document.createElement("tr");
        row.innerHTML = `
          <td>${entry.time}</td>
          <td>${entry.subject}</td>
          <td>${entry.classroom}</td>
          <td>${entry.branch} - ${entry.year}</td>
          <td><a class="btn btn-sm btn-primary" href="attendance.html?subject=${encodeURIComponent(entry.subject)}&time=${encodeURIComponent(entry.time)}&classroom=${encodeURIComponent(entry.classroom)}&branch=${encodeURIComponent(entry.branch)}&year=${encodeURIComponent(entry.year)}">
            Take Attendance</a></td>
          `;
        tbody.appendChild(row);
      });
    } catch (err) {
      console.error("❌ Faculty Schedule Load Error:", err);
      tbody.innerHTML = `<tr><td colspan="5" class="text-danger text-center">Error loading schedule.</td></tr>`;
    }
  }
  
  // Call function when page loads
  loadFacultySchedule();
  // 📝 Fetch and render tasks
async function fetchTasks() {
  try {
    const res = await fetch("https://mu-intraner-portal.onrender.com/api/tasks", {
      headers: {
        Authorization: `Bearer ${token}`
      }
    });

    const tasks = await res.json();
    if (!Array.isArray(tasks)) {
      console.warn("⚠️ Unexpected response for tasks:", tasks);
      return;
    }

    const taskList = document.getElementById("taskList");
    taskList.innerHTML = "";

    tasks.forEach(task => {
      const li = document.createElement("li");
      li.className = "list-group-item bg-transparent d-flex align-items-center justify-content-between";

      li.innerHTML = `
        <div>
          <input type="checkbox" ${task.completed ? "checked" : ""} onchange="toggleComplete('${task._id}')">
          <span class="ms-2 task-text" style="text-decoration: ${task.completed ? 'line-through' : 'none'}; opacity: ${task.completed ? '0.5' : '1'};">
            ${task.text}
          </span>
        </div>
        <button class="btn btn-sm btn-danger" onclick="deleteTask('${task._id}')"><i class="fa fa-times"></i></button>
      `;

      taskList.appendChild(li);
    });
  } catch (err) {
    console.error("❌ Error loading tasks:", err);
  }
}

// ➕ Add new task
async function addTask() {
  const input = document.getElementById("taskInput");
  const text = input.value.trim();
  if (!text) return;

  try {
    await fetch("https://mu-intraner-portal.onrender.com/api/tasks", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify({ text })
    });

    input.value = "";
    fetchTasks();
  } catch (err) {
    console.error("❌ Error adding task:", err);
  }
}

// ✅ Toggle task completion
async function toggleComplete(taskId) {
  try {
    await fetch(`https://mu-intraner-portal.onrender.com/api/tasks/${taskId}`, {
      method: "PATCH",
      headers: {
        Authorization: `Bearer ${token}`
      }
    });

    fetchTasks();
  } catch (err) {
    console.error("❌ Error toggling task:", err);
  }
}

// ❌ Delete task
async function deleteTask(taskId) {
  try {
    await fetch(`https://mu-intraner-portal.onrender.com/api/tasks/${taskId}`, {
      method: "DELETE",
      headers: {
        Authorization: `Bearer ${token}`
      }
    });

    fetchTasks();
  } catch (err) {
    console.error("❌ Error deleting task:", err);
  }
}