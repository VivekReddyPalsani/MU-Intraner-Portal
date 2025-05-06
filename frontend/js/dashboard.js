// Auth check & user info
const token = localStorage.getItem("token");
const user = JSON.parse(localStorage.getItem("user"));

if (!token || !user) {
    alert("Please login first!");
    window.location.href = "signin.html";
} else if (user.role !== "student") {
    window.location.href = "faculty.html"; // Redirect faculty to their dashboard
} else {
    document.querySelectorAll(".username-placeholder").forEach(el => {
        el.textContent = user.name;
    });

    document.querySelectorAll(".userrole-placeholder").forEach(el => {
        el.textContent = user.role.charAt(0).toUpperCase() + user.role.slice(1);
    });

    // Call functions to load dashboard data
    fetchTasks();
    loadTodaySchedule(); // Keep the call to loadTodaySchedule here as requested
}

// Logout function
function logout() {
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    window.location.href = "signin.html";
}

// Helper function to escape HTML (Good practice to prevent XSS)
function escapeHtml(unsafe) {
    if (typeof unsafe !== 'string') {
        return unsafe === null || unsafe === undefined ? "" : String(unsafe);
    }
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}


// Fetch and render tasks
async function fetchTasks() {
    try {
        const currentToken = localStorage.getItem("token");
        if (!currentToken) {
            console.error("JWT token not found for fetching tasks.");
            const taskList = document.getElementById("taskList");
            if(taskList) taskList.innerHTML = '<li class="list-group-item bg-transparent text-center text-danger">Authentication token missing for tasks.</li>';
            return;
        }

        const res = await fetch("http://localhost:5000/api/tasks", {
            headers: {
                Authorization: `Bearer ${currentToken}`
            }
        });

        if (!res.ok) {
            const errorText = await res.text();
            throw new Error(`HTTP error! status: ${res.status}, message: ${errorText}`);
        }

        const tasks = await res.json();
        if (!Array.isArray(tasks)) {
            console.warn("Unexpected response for tasks:", tasks);
            const taskList = document.getElementById("taskList");
            if(taskList) taskList.innerHTML = '<li class="list-group-item bg-transparent text-center text-danger">Unexpected data format for tasks.</li>';
            return;
        }

        const taskList = document.getElementById("taskList");
        if (!taskList) {
            console.error("Task list element not found!");
            return;
        }
        taskList.innerHTML = ""; // Clear previous tasks

        if (tasks.length === 0) {
            taskList.innerHTML = '<li class="list-group-item bg-transparent text-center text-muted">No tasks found.</li>';
        } else {
            tasks.forEach(task => {
                const li = document.createElement("li");
                li.className = "list-group-item bg-transparent d-flex align-items-center justify-content-between";

                li.innerHTML = `
                    <div>
                        <input type="checkbox" ${task.completed ? "checked" : ""} onchange="toggleComplete('${escapeHtml(task._id)}')">
                        <span class="ms-2 task-text" style="text-decoration: ${task.completed ? 'line-through' : 'none'}; opacity: ${task.completed ? '0.5' : '1'};">
                            ${escapeHtml(task.text)}
                        </span>
                    </div>
                    <button class="btn btn-sm btn-danger" onclick="deleteTask('${escapeHtml(task._id)}')"><i class="fa fa-times"></i></button>
                `;
                taskList.appendChild(li);
            });
        }

    } catch (err) {
        console.error("❌ Error loading tasks:", err);
        const taskList = document.getElementById("taskList");
        if(taskList) taskList.innerHTML = '<li class="list-group-item bg-transparent text-center text-danger">Error loading tasks.</li>';
    }
}

// Add new task
// Ensure addTask is called from an element in index.html, e.g., <button onclick="addTask()">
async function addTask() {
    const input = document.getElementById("taskInput");
    if (!input) {
        console.error("Task input element not found!");
        return;
    }
    const text = input.value.trim();
    if (!text) return;

    try {
        const currentToken = localStorage.getItem("token");
        if (!currentToken) {
            console.error("JWT token not found for adding task.");
            alert("Authentication token missing. Cannot add task.");
            return;
        }

        await fetch("http://localhost:5000/api/tasks", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${currentToken}`
            },
            body: JSON.stringify({ text })
        });

        input.value = ""; // Clear the input field
        fetchTasks(); // Refresh the task list
    } catch (err) {
        console.error("❌ Error adding task:", err);
        alert("Failed to add task.");
    }
}

// Toggle task completion
// Ensure toggleComplete is called from an element in index.html, e.g., <input type="checkbox" onchange="toggleComplete('...')">
async function toggleComplete(taskId) {
    if (!taskId) {
        console.error("Task ID is missing for toggling completion.");
        return;
    }
    try {
        const currentToken = localStorage.getItem("token");
        if (!currentToken) {
            console.error("JWT token not found for toggling task.");
            alert("Authentication token missing. Cannot update task.");
            return;
        }

        const res = await fetch(`http://localhost:5000/api/tasks/${taskId}`, {
            method: "PATCH",
            headers: {
                Authorization: `Bearer ${currentToken}`
            }
        });

        if (!res.ok) {
            const errorText = await res.text();
            throw new Error(`HTTP error! status: ${res.status}, message: ${errorText}`);
        }

        fetchTasks(); // Refresh the task list
    } catch (err) {
        console.error("❌ Error toggling task:", err);
        alert("Failed to update task completion.");
    }
}

// Delete task
// Ensure deleteTask is called from an element in index.html, e.g., <button onclick="deleteTask('...')">
async function deleteTask(taskId) {
    // Optional: Add a confirmation dialog before deleting
    if (!confirm("Are you sure you want to delete this task?")) {
        return;
    }
    if (!taskId) {
        console.error("Task ID is missing for deletion.");
        return;
    }

    try {
        const currentToken = localStorage.getItem("token");
        if (!currentToken) {
            console.error("JWT token not found for deleting task.");
            alert("Authentication token missing. Cannot delete task.");
            return;
        }

        const res = await fetch(`http://localhost:5000/api/tasks/${taskId}`, {
            method: "DELETE",
            headers: {
                Authorization: `Bearer ${currentToken}`
            }
        });

        if (!res.ok) {
            // Handle cases where the task might not exist or other server errors
            const errorText = await res.text();
            throw new Error(`HTTP error! status: ${res.status}, message: ${errorText}`);
        }
        // No need to parse JSON for 204 No Content success


        fetchTasks(); // Refresh the task list
    } catch (err) {
        console.error("❌ Error deleting task:", err);
        alert("Failed to delete task.");
    }
}

// Load Today's Schedule - KEPT as requested
async function loadTodaySchedule() {
    try {
        const currentToken = localStorage.getItem("token");
        if (!currentToken) {
            console.error("JWT token not found for loading schedule.");
            const tbody = document.getElementById("schedule-body");
            if (tbody) tbody.innerHTML = `<tr><td colspan="6" class="text-center text-danger">Authentication token missing.</td></tr>`;
            return;
        }
        const res = await fetch("http://localhost:5000/api/schedule/today", {
            headers: {
                Authorization: `Bearer ${currentToken}`
            }
        });

        if (!res.ok) {
            const errorText = await res.text();
            throw new Error(`HTTP error! status: ${res.status}, message: ${errorText}`);
        }

        const data = await res.json();
        const tbody = document.getElementById("schedule-body");
        if (!tbody) {
            console.error("Schedule table body element not found!");
            return;
        }
        tbody.innerHTML = ""; // Clear existing content

        if (!Array.isArray(data) || data.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="text-center text-muted">No classes scheduled today</td></tr>`;
            return;
        }

        const today = new Date().toLocaleDateString('en-GB');

        data.forEach(entry => {
            const tr = document.createElement("tr");
            // Generate table row HTML with data attributes for review button
            // Ensure your backend /api/schedule/today now returns facultyId, facultyName, time, subject, classroom
            tr.innerHTML = `
                <td>${escapeHtml(today)}</td>
                <td>${escapeHtml(entry.time || 'N/A')}</td>
                <td>${escapeHtml(entry.subject || 'N/A')}</td>
                <td>${escapeHtml(entry.classroom || 'N/A')}</td>
                <td>${escapeHtml(entry.facultyName || 'N/A')}</td>
                <td>
                    <button class="btn btn-sm btn-danger review-btn"
                    data-subject="${escapeHtml(entry.subject || '')}"
                    data-facultyname="${escapeHtml(entry.facultyName || '')}"
                    data-bs-toggle="modal" data-bs-target="#reviewModal">
                    Review
                    </button>
                </td>
            `;
            tbody.appendChild(tr);
        });

        // Removed the old forEach loop attaching click listeners here

    } catch (err) {
        console.error("❌ Could not load schedule:", err);
        const tbody = document.getElementById("schedule-body");
        if (tbody) tbody.innerHTML = `<tr><td colspan="6" class="text-center text-danger">Error loading schedule</td></tr>`;
    }
}


// --- Handle Review Button Click (using event delegation on schedule table) ---
// Ensure scheduleTableBody and reviewModalElement are retrieved after DOMContentLoaded
let scheduleTableBody = null;
let reviewModalElement = null;


// Handle the click event using delegation
function handleReviewButtonClick(event) {
    const target = event.target;
    // Use closest() to find the clicked button, even if an icon inside was clicked
    const reviewButton = target.closest(".review-btn");

    if (reviewButton) {
        const subject = reviewButton.getAttribute("data-subject");
        const facultyName = reviewButton.getAttribute("data-facultyname");

        // --- Restriction Logic ---
        // **IMPORTANT:** Replace with the actual names of the faculty teaching these subjects from your data
        const allowedFacultyNames = ["Mr. Arun Avinash Chauhan", "Dr. Ravi Kishore Vasala"]; // Replace with actual faculty names
        const allowedSubjects = ["Software Engineering", "Introduction to Modern Cryptography"]; // Replace with actual subject names

        // Check if the subject is allowed AND the faculty name is one of the allowed ones
        const isAllowed = allowedSubjects.includes(subject) && allowedFacultyNames.includes(facultyName);

        if (!isAllowed) {
            alert(`Reviews are currently enabled only for ${allowedSubjects.join(' and ')} taught by ${allowedFacultyNames.join(' and ')}. Please give a review for one of these classes if available in your schedule.`);
            // Prevent the modal from showing by stopping the event propagation
            event.stopPropagation();
            return; // Stop further execution in this handler
        }
        // --- End Restriction Logic ---

        // Populate modal fields - ensure elements exist in index.html
        const reviewSubjectInput = document.getElementById("reviewSubject");
        const reviewFacultyInput = document.getElementById("reviewFaculty");

        if (reviewSubjectInput) reviewSubjectInput.value = subject; else console.error("reviewSubject input not found");
        if (reviewFacultyInput) reviewFacultyInput.value = facultyName; else console.error("reviewFaculty input not found");

        // Note: The modal will be shown by Bootstrap's data attributes on the button.
        // Resetting of form is handled by modal event listeners below.

    }
}


// --- Handle Review Form Submission ---
let reviewForm = null; // Get form element after DOMContentLoaded

// --- DOMContentLoaded Listener ---
// This runs after the HTML is fully loaded and parsed.
document.addEventListener("DOMContentLoaded", async () => {

    // Retrieve elements here that might not be available until DOMContentLoaded
    scheduleTableBody = document.getElementById("schedule-body");
    reviewModalElement = document.getElementById('reviewModal');
    reviewForm = document.getElementById('reviewForm');
    // Retrieve the new rating input element
    const reviewRatingInput = document.getElementById('reviewRatingInput');




    // --- MODIFY MODAL SHOW/HIDE LISTENERS ---
    if (reviewModalElement) {
        reviewModalElement.addEventListener('hidden.bs.modal', function () {
            if(reviewForm) reviewForm.reset(); // Reset the form fields
            // Clear hidden faculty ID and text inputs
            const reviewSubjectInput = document.getElementById("reviewSubject");
            const reviewFacultyInput = document.getElementById("reviewFaculty");
            if(reviewSubjectInput) reviewSubjectInput.value = '';
            if(reviewFacultyInput) reviewFacultyInput.value = '';
             // Clear the new rating input field
            if(reviewRatingInput) reviewRatingInput.value = '';
        });

        reviewModalElement.addEventListener('show.bs.modal', function () {
            const reviewTextarea = document.getElementById("reviewText");
            if(reviewTextarea) reviewTextarea.value = ""; // Clear review text
            // Clear the new rating input field when modal shows
             if(reviewRatingInput) reviewRatingInput.value = '';
        });
    } else {
        console.error("Review modal element with id 'reviewModal' not found!");
    }


    // Add event delegation listener for review buttons after the schedule body is available
    if (scheduleTableBody) {
        scheduleTableBody.addEventListener("click", handleReviewButtonClick);
    } else {
        console.error("Schedule table body element with id 'schedule-body' not found!");
    }


    // --- MODIFY FORM SUBMISSION LISTENER ---
    if (reviewForm) {
        reviewForm.addEventListener('submit', async function(event) {
            event.preventDefault();

            const subject = document.getElementById('reviewSubject').value;
            const facultyName = document.getElementById('reviewFaculty').value;
            const reviewText = document.getElementById('reviewText').value;
            // Get rating from the new number input
            const rating = parseInt(document.getElementById('reviewRatingInput').value);

            // Update validation for number input
            if (isNaN(rating) || rating < 1 || rating > 5) {
                 alert('Please provide a valid rating between 1 and 5.');
                 return;
            }
            if (!subject || !facultyName ) {
                 alert('Missing required review information (Subject or Faculty). Cannot submit review.');
                 console.error('Missing required review information:', {subject, facultyName});
                 return;
            }


            const reviewPayload = {
                subject,
                facultyName,
                facultyId,
                rating, // Use the rating from the input
                reviewText
            };

            try {
                const currentToken = localStorage.getItem("token");
                if (!currentToken) {
                    console.error("JWT token not found for submitting review.");
                    alert("Authentication token missing. Cannot submit review.");
                    return;
                }

                const res = await fetch("http://localhost:5000/api/reviews", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        Authorization: "Bearer " + currentToken
                    },
                    body: JSON.stringify(reviewPayload)
                });

                const result = await res.json();

                if (res.ok) {
                    alert("✅ Review submitted successfully!");
                    const modal = bootstrap.Modal.getInstance(reviewModalElement);
                    if (modal) {
                        modal.hide();
                    }
                } else {
                    const errorMessage = result.message || 'Unknown error';
                    alert(`❌ Failed to submit review: ${errorMessage}`);
                    console.error("❌ Backend error submitting review:", result);
                }

            } catch (err) {
                console.error("❌ Error submitting review:", err);
                alert("An error occurred while submitting your review. Please try again.");
            }
        });
    } else {
        console.error("Review form element with id 'reviewForm' not found!");
    }


    // --- Load Attendance Summary ---
    try {
        const currentToken = localStorage.getItem("token");
        if (!currentToken) {
            console.error("JWT token not found for attendance summary in DOMContentLoaded.");
            const tbody = document.querySelector("#subjectAttendanceTableBody");
            if (tbody) tbody.innerHTML = `<tr><td colspan="4" class="text-center text-danger">Authentication token missing.</td></tr>`;
            return;
        }

        const res = await fetch("http://localhost:5000/api/attendance/summary", {
            headers: {
                Authorization: "Bearer " + currentToken,
            },
        });

        if (!res.ok) {
            const errorText = await res.text();
            throw new Error(`HTTP error! status: ${res.status}, message: ${errorText}`);
        }

        const data = await res.json();

        const tbody = document.querySelector("#subjectAttendanceTableBody");
        if (!tbody) {
            console.error("Attendance table body element not found!");
            return;
        }
        tbody.innerHTML = "";

        if (!Array.isArray(data) || data.length === 0) {
            tbody.innerHTML = `<tr><td colspan="4" class="text-center text-muted">No attendance records found.</td></tr>`;
        } else {
            data.forEach(row => {
                const tr = document.createElement("tr");
                tr.innerHTML = `
                    <td>${escapeHtml(row.subject || 'N/A')}</td>
                    <td>${escapeHtml(row.total || 0)}</td>
                    <td>${escapeHtml(row.attended || 0)}</td>
                    <td>${escapeHtml(row.percentage || '0.00')}%</td>
                `;
                tbody.appendChild(tr);
            });
        }

    } catch (err) {
        console.error("❌ Error loading attendance summary:", err);
        const tbody = document.querySelector("#subjectAttendanceTableBody");
        if (tbody) tbody.innerHTML = `<tr><td colspan="4" class="text-center text-danger">Error loading attendance summary.</td></tr>`;
    }

    // Note: loadTodaySchedule() is called outside this DOMContentLoaded listener
});